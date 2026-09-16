rule sig_20160526_a12f4a71d9399dc5ee0a145df17546b4 {
  meta:
    description = "datamaliciousorder - file 20160526_a12f4a71d9399dc5ee0a145df17546b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d851a8f01e840ba55cd7c50157568c51947375e891f7476f707c406eac2159fe"

  strings:
    $s1  = "IlluRGnqaHav);else if (YtXwoTVQm == (238 + Math.round((Math.pow(Math.sin(292), 2) + Math.pow(Math.cos(292), 2) - 1))-174)) NLYKk" ascii
    $s2  = "function bNVlDiiAj(nfXceJKzKLFVL) {var wyXcnqKxacsDRvMsWWiQXf = vOYjzdeLXU.join(rJdIYNAJLbTdwcID[0]);var micmJCIlluRGnqaHav, Hkp" ascii
    $s3  = "nd((Math.pow(Math.sin(214), 2) + Math.pow(Math.cos(214), 2) - 1))-503) | jBgMyqpqaQUKlAjsKZlc<< (278 + Math.round((Math.pow(Math" ascii
    $s4  = "(646), 2) + Math.pow(Math.cos(646), 2) - 1))-19) & 0xff;HkpllPsySsuJXStxTnETWXfU = bJwaTxkJVKFWMurNRF>> (407 + Math.round((Math." ascii
    $s5  = "function LzOHHXA(ewFouGTfzbzpImXhni,YopnZHOxtnTRYty){return ewFouGTfzbzpImXhni.charAt(YopnZHOxtnTRYty);}" fullword ascii
    $s6  = "function bNVlDiiAj(nfXceJKzKLFVL) {var wyXcnqKxacsDRvMsWWiQXf = vOYjzdeLXU.join(rJdIYNAJLbTdwcID[0]);var micmJCIlluRGnqaHav, Hkp" ascii
    $s7  = "H += NnqMddaM(micmJCIlluRGnqaHav, HkpllPsySsuJXStxTnETWXfU);else NLYKkH += wRCRbwQGnO(micmJCIlluRGnqaHav, HkpllPsySsuJXStxTnETWX" ascii
    $s8  = "fU, NjQYvSpRKLxONBgHNEPp);} while (aTKUJPBpOnhkrram < nfXceJKzKLFVL.length);return NLYKkH;}" fullword ascii
    $s9  = "function SN(AlNzFYJtypJb){return String.fromCharCode(AlNzFYJtypJb);}" fullword ascii
    $s10 = "function NnqMddaM(aAPymaAgcaCNagRsapUuBMWz,GJaeePWatTsVLQUbWDcmL){return String.fromCharCode(aAPymaAgcaCNagRsapUuBMWz,GJaeePWatT" ascii
    $s11 = "function wRCRbwQGnO(TSZaNBnfSKjIofcikQoBC,XFFLqIxxXeFKQYNKrATcfUhg,hrkUEYiUfJUEtNlBEqJcAW){return String.fromCharCode(TSZaNBnfSK" ascii
    $s12 = "function NnqMddaM(aAPymaAgcaCNagRsapUuBMWz,GJaeePWatTsVLQUbWDcmL){return String.fromCharCode(aAPymaAgcaCNagRsapUuBMWz,GJaeePWatT" ascii
    $s13 = "function wRCRbwQGnO(TSZaNBnfSKjIofcikQoBC,XFFLqIxxXeFKQYNKrATcfUhg,hrkUEYiUfJUEtNlBEqJcAW){return String.fromCharCode(TSZaNBnfSK" ascii
    $s14 = "function ztoNmzvWgQXGR(cyZaLqpPUILTDeLnTCZCA,ZOCwJfobb){return cyZaLqpPUILTDeLnTCZCA.indexOf(ZOCwJfobb);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}