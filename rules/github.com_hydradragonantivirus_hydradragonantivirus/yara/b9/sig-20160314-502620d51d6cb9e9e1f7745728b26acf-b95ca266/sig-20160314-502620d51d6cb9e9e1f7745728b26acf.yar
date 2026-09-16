rule sig_20160314_502620d51d6cb9e9e1f7745728b26acf {
  meta:
    description = "datamaliciousorder - file 20160314_502620d51d6cb9e9e1f7745728b26acf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87e7e15d212bd0cf3c49f6db66fb04a68bc7043fdd6ea0941adffed3fd783288"

  strings:
    $s1 = "while (NaJQGeNqc.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s2 = "lDZRoyuJJ + cIFNR + uGfPHBDEBmi + YLBhkxKVYBMkt + TFRcsskz + LrDRWLMjtwLo + bzsaFC, false);" fullword ascii
    $s3 = "NaJQGeNqc.open(sXwlObti + EKoLieQLS, sEnPaUna + vtnMoWDSUS + KOqxGRiTMA + DOrQDxf + kmfbl + hPAgMm + lUYcxCiY + LuAQme + QAulVKM" ascii
    $s4 = "return OCatTYc + zYKJDKzlM + WuE + ZCdpn + bOobmfv + Zgc + wirwEmTN" fullword ascii
    $s5 = "function WhfNYgWuzNuW(n)" fullword ascii
    $s6 = "function stBhcDbrGwCT(fname)" fullword ascii
    $s7 = "var DwhvCAaBHn = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}