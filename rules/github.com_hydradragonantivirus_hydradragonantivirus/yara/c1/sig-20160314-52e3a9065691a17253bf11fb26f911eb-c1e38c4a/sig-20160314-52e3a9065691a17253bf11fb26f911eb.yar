rule sig_20160314_52e3a9065691a17253bf11fb26f911eb {
  meta:
    description = "datamaliciousorder - file 20160314_52e3a9065691a17253bf11fb26f911eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8145f08fd9f79bdacdf2405b53dfae158182d45ebfd205856ed009384a8c124"

  strings:
    $s1 = "MNnRNboJ = WScript.CreateObject(VUFDlQOId + ziNK + Lxqd + PXszyGh + fHJEgRVPAqgQ + aljbKhPzVqJjRH);" fullword ascii
    $s2 = "while (bLDoeXnlvj.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "return LjMfd + ildytaeJGgCuWn + wlB + gQWTmfPYP + nlxwhQChfs" fullword ascii
    $s4 = "v + DjqLBF + TakFsSA + ZobeJNDNRHxYIa + KfCLmkH + fBoqeLxA + kPpUXp + Lws + hGTMJP, false);" fullword ascii
    $s5 = "bLDoeXnlvj.open(XGYRE + gZKmgaKXyfis + wZeVdKpqI, lDJYMGHUGWdxvpn + OKshmaFzOesUQs + pQIRnXvFP + bmFXiJ + prc0 + OzQnoUHNSsnrupu" ascii
    $s6 = "var wiPjqs = new Date();" fullword ascii
    $s7 = "function yDyDdACPH(n)" fullword ascii
    $s8 = "var ziNK = \"OD\";" fullword ascii
    $s9 = "function dsoIQwu(fname)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}