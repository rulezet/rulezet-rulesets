rule sig_20160526_2af73038ea6921e7a9da8e808126a038 {
  meta:
    description = "datamaliciousorder - file 20160526_2af73038ea6921e7a9da8e808126a038.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f5f33410448ec57a4d9a543cd338079c2a3dcb32dc24708428580ce03c3bfad"

  strings:
    $s1  = "function eNxZo(VPgIqVjRUaCnz) {var pRzqOzWdYbdjtPQqXM = qFmbwcPUp.join(JXEmYuq[0]);var mOasgdNz, eHWjHQmwhJsYvskDoUQo, woBLJEepK" ascii
    $s2  = "ow(Math.cos(402), 2) - 1))-445)) yLRVgDgrK += awEpNhpAAQuBiNFDSSUTAPlH(mOasgdNz, eHWjHQmwhJsYvskDoUQo);else yLRVgDgrK += NHQsEUz" ascii
    $s3  = " - 1))-307)) yLRVgDgrK += wS(mOasgdNz);else if (lYXLLdEiGUsADrGdUxpcKg == (509 + Math.round((Math.pow(Math.sin(402), 2) + Math.p" ascii
    $s4  = ".sin(369), 2) + Math.pow(Math.cos(369), 2) - 1))-234) | SrknohhC<< (891 + Math.round((Math.pow(Math.sin(399), 2) + Math.pow(Math" ascii
    $s5  = " illhRsNdUAC(pRzqOzWdYbdjtPQqXM,efDkhJQrpYjCdT(VPgIqVjRUaCnz,plaAlZuGK++));szJrbCQt = YdfJlCb<< (252 + Math.round((Math.pow(Math" ascii
    $s6  = "function efDkhJQrpYjCdT(JxtnuubpZdGVaDVsyBbI,RHGTqfuPoiohlZeqD){return JxtnuubpZdGVaDVsyBbI.charAt(RHGTqfuPoiohlZeqD);}" fullword ascii
    $s7  = "function awEpNhpAAQuBiNFDSSUTAPlH(yvxGq,lXYryoJJZIatHeKuIvrltSN){return String.fromCharCode(yvxGq,lXYryoJJZIatHeKuIvrltSN);}" fullword ascii
    $s8  = "function illhRsNdUAC(pwIKraloObsE,XaxVAeYF){return pwIKraloObsE.indexOf(XaxVAeYF);}" fullword ascii
    $s9  = "function NHQsEUzPrZkxCC(nfmaRTmD,yURyMIKOmuqzYaLjeNNXjeZ,ldMqNilmGYulWxSa){return String.fromCharCode(nfmaRTmD,yURyMIKOmuqzYaLje" ascii
    $s10 = "function wS(RdbelPRWav){return String.fromCharCode(RdbelPRWav);}" fullword ascii
    $s11 = "function NHQsEUzPrZkxCC(nfmaRTmD,yURyMIKOmuqzYaLjeNNXjeZ,ldMqNilmGYulWxSa){return String.fromCharCode(nfmaRTmD,yURyMIKOmuqzYaLje" ascii
    $s12 = "function eNxZo(VPgIqVjRUaCnz) {var pRzqOzWdYbdjtPQqXM = qFmbwcPUp.join(JXEmYuq[0]);var mOasgdNz, eHWjHQmwhJsYvskDoUQo, woBLJEepK" ascii
    $s13 = "PrZkxCC(mOasgdNz, eHWjHQmwhJsYvskDoUQo, woBLJEepKjAohw);} while (plaAlZuGK < VPgIqVjRUaCnz.length);return yLRVgDgrK;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}