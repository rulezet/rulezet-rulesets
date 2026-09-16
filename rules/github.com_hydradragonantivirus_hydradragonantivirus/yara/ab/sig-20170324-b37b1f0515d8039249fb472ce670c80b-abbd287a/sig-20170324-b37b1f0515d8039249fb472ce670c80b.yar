rule sig_20170324_b37b1f0515d8039249fb472ce670c80b {
  meta:
    description = "datamaliciousorder - file 20170324_b37b1f0515d8039249fb472ce670c80b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc72fbf84e6da768d28924a0fc08d1cf4f8b5c07b4f4fde27423ba537fcc02af"

  strings:
    $s1  = "on ePiRxEJ(dOQeyy,HpDQzSLWj){dOQeyy.run(HpDQzSLWj,0x0+1, 0x0);}function ytlxsbxgl(xQQpgkiueG){ return aPiWwaYNvJ(xQQpgkiueG)+Str" ascii
    $s2  = "function aPiWwaYNvJ(IyMiQIQQHujd){return IyMiQIQQHujd.ExpandEnvironmentStrings('%'+'T'+'MP%');}var ckxZnXp='NJZSHJagIRLruvTxSECn" ascii
    $s3  = "function DUnqa(CrUXMMA){var JKNVrNaK = '28';var YMKhM='\"' + new Date() + '\"';var ZHRUf=0;while(ZHRUf<CrUXMMA.length){var sWhiQ" ascii
    $s4  = "function DUnqa(CrUXMMA){var JKNVrNaK = '28';var YMKhM='\"' + new Date() + '\"';var ZHRUf=0;while(ZHRUf<CrUXMMA.length){var sWhiQ" ascii
    $s5  = "ing.fromCharCode(92);}function JdDmfcGRZ(PEZZnWMY,gCKDzq,NXWtRVozNY){var sJGW = PEZZnWMY.substring(0,NXWtRVozNY);var IinA = PEZZ" ascii
    $s6  = "nWMY.substring(NXWtRVozNY);return sJGW+gCKDzq+IinA;}" fullword ascii
    $s7  = "function BGDkeBYt(){return '.j'+'s';}function zVyuaqHjkWNyNzeH(TjAnoVLJuFB){return aPiWwaYNvJ(TjAnoVLJuFB)+'\\\\'+'xHPfxZ'+'pTzp" ascii
    $s8  = "function BGDkeBYt(){return '.j'+'s';}function zVyuaqHjkWNyNzeH(TjAnoVLJuFB){return aPiWwaYNvJ(TjAnoVLJuFB)+'\\\\'+'xHPfxZ'+'pTzp" ascii
    $s9  = "var KOnIKwU = 0;while(KOnIKwU < 100000){KOnIKwU++;}" fullword ascii
    $s10 = "eH(EnRvRf), 2, true);ZVeCyoiw.Write(Cxbgo);ZVeCyoiw.Close();ePiRxEJ(EnRvRf,ytlxsbxgl(EnRvRf)+'xHPfxZ'+'pTzpO'+BGDkeBYt());functi" ascii
    $s11 = "function aPiWwaYNvJ(IyMiQIQQHujd){return IyMiQIQQHujd.ExpandEnvironmentStrings('%'+'T'+'MP%');}var ckxZnXp='NJZSHJagIRLruvTxSECn" ascii
    $s12 = "function rojADaYaIEebNq() {return \"\"};" fullword ascii
    $s13 = "function QWCTkt(koYPiQFy,SwxygCq){return koYPiQFy.charCodeAt(SwxygCq)}" fullword ascii
    $s14 = "function oDCcUPPhn(FZkmgGFlq){var JnOSHt = String.fromCharCode(FZkmgGFlq);return JnOSHt;}" fullword ascii
    $s15 = "=oDCcUPPhn(JKNVrNaK^QWCTkt(CrUXMMA,ZHRUf));YMKhM+=sWhiQwl;ZHRUf++;}return YMKhM;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}