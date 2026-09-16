rule sig_20160314_34df4a8c5e0802dbb4ae1643137e712c {
  meta:
    description = "datamaliciousorder - file 20160314_34df4a8c5e0802dbb4ae1643137e712c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb13f7c08be14a589ed1cc4027b3365ee127755f60cab15417ac7318df045839"

  strings:
    $s1 = "while (kXIlfFuLjtQ.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s2 = "return GCsijdOFIck + WqfUrwvVu + oKJBHTRWMSzYiG + niVHHqynLD + icSKQCLayD + ocOEu + CmV + eBmksvStTmou" fullword ascii
    $s3 = "sLWeaNDdl + GAagdldXszd + sFyUpNI, false);" fullword ascii
    $s4 = "kXIlfFuLjtQ.open(QJlkPtmLwkd + qOxXLrdoc, jUNzxVR + urx + hJbOTgK + RGegD + RkRlFcd + iGqv + wXmcpe + ixD + XAjfknlvJzZSya + KOB" ascii
    $s5 = "var tCu = new Date();" fullword ascii
    $s6 = "function dyXtxWC(fname)" fullword ascii
    $s7 = "function DeBz(n)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}