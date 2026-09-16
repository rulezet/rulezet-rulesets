rule sig_20160315_e5b714ce6f408b239ff44d9b988bf5e5 {
  meta:
    description = "datamaliciousorder - file 20160315_e5b714ce6f408b239ff44d9b988bf5e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c209b7786ca5023b015d1ea3ee8fd81c81292bbbe9954140ca7de3994a8425f"

  strings:
    $s1 = "function JlswcFgYHKvjD(TAXdOhCKhg){WshShell[kIOK + DfdyswguaZpAlRG](TAXdOhCKhg, 0, 0);}" fullword ascii
    $s2 = "while (dQZfBp.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "function MvEKLcirHYnFRfF(n){return qoz + ptOUpMuUSgtbIp + twRGIP + MAOUtweRuskUfy + dgYjXRPEPfGV + pmrx + GnTTeJZTyI;}" fullword ascii
    $s4 = "dQZfBp[DkpidnzOqisg + oSvFlUKfYW + GCsiNU](XKmAmq + ZkFGmb, qCyNnjRbbaIfPXO + xbCmjbkvEeET + tsQder + rqrnQ + VHTPR + Bqwxry + h" ascii
    $s5 = "xi + wsDdERCvlvG + hJroRoi + VvIruZ + LAYzMSURCXkyTd + khgI + npP0 + RuPn, false);" fullword ascii
    $s6 = "var ZqQEM = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}