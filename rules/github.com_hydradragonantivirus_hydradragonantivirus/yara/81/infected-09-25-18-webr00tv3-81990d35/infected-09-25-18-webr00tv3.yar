rule infected_09_25_18_webr00tv3 {
  meta:
    description = "shell2 - file webr00tv3.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-09-25"
    hash1       = "c9c6155d2f88fe2e651768dd1f5dc69fb8470c612dd46488d2b475a004036026"

  strings:
    $x1  = "<?php $OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64');$OOO0000O0=$OOO000000{4}.$OOO000000{9}.$OOO000" ascii
    $s2  = "SUlsSUk9J2ZpbGUnOyRJSUlJSUlJSUlJMUk9J3N5bWxpbmsnOyRJSUlJSUlJSUlJbDE9J2Z3cml0ZSc7JElJSUlJSUlJSUlsbD0nZm9wZW4nOyRJSUlJSUlJSUlJSWw9" ascii  
    $s3  = "SUlJSWwxSTFJPSdoaWdobGlnaHRfZmlsZSc7JElJSUlJSUlsMUlsMT0nc2hvd19zb3VyY2UnOyRJSUlJSUlJbDFJbGw9J2h0bWxlbnRpdGllcyc7JElJSUlJSUlsMUls" ascii  
    $s4  = "bGxsSUk9J2h0bWxzcGVjaWFsY2hhcnMnOyRJSUlJSUlJbGxJSTE9J2NobW9kJzskSUlJSUlJSWxsSUlsPSdiYXNlNjRfZGVjb2RlJzskSUlJSUlJSWxJMTFJPSdmY2xv" ascii  
    $s5  = "ST0nZnJlYWQnOyRJSUlJSUlJbGwxbGw9J3N0cmlwY3NsYXNoZXMnOyRJSUlJSUlJbGwxSTE9J2ZpbGVzaXplJzskSUlJSUlJSWxsMUlJPSd1bmxpbmsnOyRJSUlJSUlJ" ascii  
    $s6  = "tUHBRcVNzVnZYeFp6MDEyMzQ1Njc4OSsvPScsJ0FCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5Ky8nKSk" ascii  
    $s7  = "c2VyX2Fib3J0JzskSUlJSUlJSTFJbEkxPSdpc19maWxlJzskSUlJSUlJSTFJSTFsPSdteXNxbF9xdWVyeSc7JElJSUlJSUkxSUlsMT0nbXlzcWxfY29ubmVjdCc7JElJ" ascii  
    $s8  = "ZXhlYyc7JElJSUlJSUlsSUlsST0nY3VybF9zZXRvcHQnOyRJSUlJSUlJbElJSTE9J2N1cmxfaW5pdCc7JElJSUlJSUlJMTExST0nc3ByaW50Zic7JElJSUlJSUlJMWxs" ascii  
    $s9  = "MUlJbD0ncGNsb3NlJzskSUlJSUlJSTExSUlJPSdmZ2V0cyc7JElJSUlJSUkxbDExbD0nZmVvZic7JElJSUlJSUkxbDExST0ncG9wZW4nOyRJSUlJSUlJMWwxSUk9J3Jv" ascii  
    $s10 = "bGxsMTE9J3JtZGlyJzskSUlJSUlJSWxsbDFsPSdjb3VudCc7JElJSUlJSUlsbGxsMT0nZXhwbG9kZSc7JElJSUlJSUlsbGxJbD0naXNfd3JpdGFibGUnOyRJSUlJSUlJ" ascii  
    $s11 = "dW5kJzskSUlJSUlJSTFsbDFJPSdmc29ja29wZW4nOyRJSUlJSUlJMWxsbDE9J3JhbmQnOyRJSUlJSUlJMWxJMTE9J3RpbWUnOyRJSUlJSUlJMWxJbDE9J2lnbm9yZV91" ascii  
    $s12 = "XHr8Xk10Pk1nuBmcJdlymBTw5F2wzUTlDH0pSBlF0h1f5foOkWzavcrfoDlLZampjGAkBC0f4fllbABfUa1kXCLfUFrleYeiHHlp2CM5Oh1nyUlYWcz09kZL7tm0hcBx" ascii
    $s13 = "wME8wPSRPT08wMDAwTzAoJE9PTzAwMDAwTygkTzBPMDBPTzAwKCRPMDAwTzBPMDAsMHgxN2MpLCdFbnRlcnlvdXdraFJIWUtOV09VVEFhQmJDY0RkRmZHZ0lpSmpMbE1" ascii  
    $s14 = "ST0nb3JkJzskSUlJSUlJSUkxSUkxPSdzdHJwb3MnOyRJSUlJSUlJSUkxSUk9J2ZpbGVvd25lcic7JElJSUlJSUlJSWwxMT0ncG9zaXhfZ2V0cHd1aWQnOyRJSUlJSUlJ" ascii  
    $s15 = "yceOlazy5T1OBByOVFyiJBrP0C25DAacwOllBO3OQTliDGaCZHB9AaLczCznaYypocrxUOMOZCM1Da1pBFyfjHeaDCznyf1aQAmpJalpXT1OBDlcQBbiLaMIza1amHBO" ascii
    $s16 = "SUlJSUlsMTExbD0nZXJlZyc7JElJSUlJSUlsMWwxMT0ncHJlZ19tYXRjaCc7JElJSUlJSUlsMWwxbD0naXNfZGlyJzskSUlJSUlJSWwxbGxsPSdpbmlfZ2V0JzskSUlJ" ascii  
    $s17 = "SUlJSTExbDFsPSdjb3B5JzskSUlJSUlJSTExbEkxPSd1cmxlbmNvZGUnOyRJSUlJSUlJMTFJMWw9J2hlYWRlcic7JElJSUlJSUkxMUkxST0nZXhlYyc7JElJSUlJSUkx" ascii  
    $s18 = "SUlsMUk9J3RyaW0nOyRJSUlJSUlJSUlsbDE9J2ZsdXNoJzskSUlJSUlJSUlJbGxJPSdwcmVnX21hdGNoX2FsbCc7JElJSUlJSUlJSWxJMT0nZXJlZ2knOyRJSUlJSUlJ" ascii  
    $s19 = "c2UnOyRJSUlJSUlJbEkxSWw9J2NoZGlyJzskSUlJSUlJSWxJbGxsPSdzdWJzdHInOyRJSUlJSUlJbElJMUk9J2N1cmxfY2xvc2UnOyRJSUlJSUlJbElJbDE9J2N1cmxf" ascii  
    $s20 = "uGoicHlavUBx3dLlpf2lhGAlzULfSfapuajORauYRULfKGBaCWjnkW0r5UAYhY1ieAjfDBypPtMkeDolcBr5STMpUclpuaMpJHlkSU0c3dLlQF0shO055caitHrleYel" ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1000KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}