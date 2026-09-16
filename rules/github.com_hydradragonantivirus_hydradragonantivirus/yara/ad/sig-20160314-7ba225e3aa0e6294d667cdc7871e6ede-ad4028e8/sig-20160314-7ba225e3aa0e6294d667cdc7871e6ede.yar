rule sig_20160314_7ba225e3aa0e6294d667cdc7871e6ede {
  meta:
    description = "datamaliciousorder - file 20160314_7ba225e3aa0e6294d667cdc7871e6ede.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9bbaa7cf0ad829b922c71774c97bb2057e0a3d7f3f486425391893afb29aded"

  strings:
    $s1 = "AOKb.open(ezVXrMeGUiCK, wINCyk + qysrAzXcYTqU + pgENIahFS + KYCymCvyhCv + NFfXJyzrA + EdMMSA + IMkYMtHTNVMjfu + WRHDIWLWu + oJlj" ascii
    $s2 = "while (AOKb.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "BPizWVCK + qCjyiXhLNeBrrb + yuaIGMZdPW, false);" fullword ascii
    $s4 = "return HFmfK + ScQZFUdcPlMa + mrQMTQVa + gkNhXFmWqD + AUbULVmi + mgIbIUlRefAnM" fullword ascii
    $s5 = "function KoVYRJhrR(fname)" fullword ascii
    $s6 = "function JjMtv(n)" fullword ascii
    $s7 = "var jfiCZ = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}