rule sig_20160520_f56f4d8ca68c9e1b40c7a1f32e3f9af8 {
  meta:
    description = "datamaliciousorder - file 20160520_f56f4d8ca68c9e1b40c7a1f32e3f9af8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d9f514136582b47886fa7e9c405c7a5fefe99cdafd245ec9d9ab9788703419a"

  strings:
    $s1  = "function MqWwsndW(VTeGg) {var BxCmbgrY=vGgSl[2];for(var MEdAA=0;MEdAA<VTeGg;MEdAA++){OqFIk+=BxCmbgrY.charAt(Math.floor(Math.rand" ascii
    $s2  = "function MqWwsndW(VTeGg) {var BxCmbgrY=vGgSl[2];for(var MEdAA=0;MEdAA<VTeGg;MEdAA++){OqFIk+=BxCmbgrY.charAt(Math.floor(Math.rand" ascii
    $s3  = "function tjFD(hstLUG,oJRQqdK){pWXK = vGgSl[11].split(vGgSl[12]);oJRQqdK.open(pWXK[0]+pWXK[2]+pWXK[3], hstLUG, false);oJRQqdK.sen" ascii
    $s4  = "function jtnCj(EcFHZlpo,VmOpk,dEwjjRTMBh){EcFHZlpo.open();EcFHZlpo.type = 1;EcFHZlpo.write(VmOpk);EcFHZlpo.position = 0;EcFHZlpo" ascii
    $s5  = "function tjFD(hstLUG,oJRQqdK){pWXK = vGgSl[11].split(vGgSl[12]);oJRQqdK.open(pWXK[0]+pWXK[2]+pWXK[3], hstLUG, false);oJRQqdK.sen" ascii
    $s6  = "function jtnCj(EcFHZlpo,VmOpk,dEwjjRTMBh){EcFHZlpo.open();EcFHZlpo.type = 1;EcFHZlpo.write(VmOpk);EcFHZlpo.position = 0;EcFHZlpo" ascii
    $s7  = "function rPccORyWg(wSkzeUNCb,lyDrcjB,GgkUZHvH){" fullword ascii
    $s8  = "gth;jVQsZRFf++) {hsSOyyp+=LiiXx[EatOah[jVQsZRFf]];}return hsSOyyp.substring(3,hsSOyyp.length);}" fullword ascii
    $s9  = "try{pHUzuxW=rPccORyWg(hzRNU[NsWK], ZYYkFXH() + vGgSl[9], 1)}catch(e){}; " fullword ascii
    $s10 = "function TrBbV(MVwYOU){return new ActiveXObject(MVwYOU);}" fullword ascii
    $s11 = "function UFiRUX(MVwYOU){return MVwYOU.ExpandEnvironmentStrings(vGgSl[10])}" fullword ascii
    $s12 = "om()*BxCmbgrY.length));}return OqFIk;}" fullword ascii
    $s13 = "if (pHUzuxW==0) break;" fullword ascii
    $s14 = "function ZYYkFXH() {var CvaF=100000;var TaTlJy = 100;return Math.random()*(CvaF-TaTlJy)+TaTlJy;}" fullword ascii
    $s15 = "function hUbok(ZcAAZVdI,EatOah,xvYJMJKyl){LiiXx=ZcAAZVdI.split(xvYJMJKyl);hsSOyyp = vGgSl[13];for(jVQsZRFf=0;jVQsZRFf<EatOah.len" ascii
    $s16 = "function hUbok(ZcAAZVdI,EatOah,xvYJMJKyl){LiiXx=ZcAAZVdI.split(xvYJMJKyl);hsSOyyp = vGgSl[13];for(jVQsZRFf=0;jVQsZRFf<EatOah.len" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}