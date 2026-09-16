rule sig_20160315_442c7c01f7c5d17e45a78fdf98cef90c {
  meta:
    description = "datamaliciousorder - file 20160315_442c7c01f7c5d17e45a78fdf98cef90c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b19eabbbeb7752fb44d933677ebac325da856af6d401bd5826193e3ae976036c"

  strings:
    $s1 = "function GOJCPiqRStjvU(sccukw){WshShell[ORAEhCD + VKmbfMExEKmE](sccukw, 0, 0);}" fullword ascii
    $s2 = "while (MGahsbDmZrdpTY.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "function eGBHkdwogqRBbVJ(n){return zBBBgrqJYDRP + qTzrkVMZvTTsJf + UDNWtg + YDJil + awnQayLQYCWq + uIXP + YkNACEbSwqnm + FGkWJkY" ascii
    $s4 = "MGahsbDmZrdpTY[usBoxgTCCZf + nhe + YMwGfHxxqE](jgymYELDHLqjOj + XUDDYjs + BsiJCuWg, FGNuQEJiZQP + xtOvJNyp + CfpLQYxQ + nmncWYeR" ascii
    $s5 = "function eGBHkdwogqRBbVJ(n){return zBBBgrqJYDRP + qTzrkVMZvTTsJf + UDNWtg + YDJil + awnQayLQYCWq + uIXP + YkNACEbSwqnm + FGkWJkY" ascii
    $s6 = "Q + Erh0 + rtRTpIpOjgZDX + zDErCVhhmGvSz + XfCvZZCVB + FRXNrmidzVbugwT, false);" fullword ascii
    $s7 = "var lfJXlcqRQVyQOJF = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}