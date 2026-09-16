rule sig_20160527_ae3b4d0fea346932c17c8b3aed7c09f1 {
  meta:
    description = "datamaliciousorder - file 20160527_ae3b4d0fea346932c17c8b3aed7c09f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22a7ca8e7cccc6a15a2ce3d4b28ccb343715ecb7299db02abb5619f459c36ac5"

  strings:
    $s1  = "function BthWOXDrh() {return WScript;}function hWJLIOOWeQVLET(){return KUPFDiTwNo.ExpandEnvironmentStrings(sNPhzwxsCXUSFU())}" fullword ascii
    $s2  = "function zixwLaREDexgavAKItj(poCicKFPCZejshDhjWLjuE,rJLWYAxzFCReTwtvCjsLa){return poCicKFPCZejshDhjWLjuE.charAt(rJLWYAxzFCReTwtv" ascii
    $s3  = "function zixwLaREDexgavAKItj(poCicKFPCZejshDhjWLjuE,rJLWYAxzFCReTwtvCjsLa){return poCicKFPCZejshDhjWLjuE.charAt(rJLWYAxzFCReTwtv" ascii
    $s4  = "function dbLUgxCgCT(MPjsZf,bOQFpoManw,fIdDCXxqUF){hEAJua=MPjsZf.split(fIdDCXxqUF);orTNJH = WKQHlYCxwrUlAwDj[14];for(amsXnorB=0;a" ascii
    $s5  = "function IXzamzgOPfzQRx(){return dbLUgxCgCT(WKQHlYCxwrUlAwDj[10],[2,4,8,10],WKQHlYCxwrUlAwDj[11]);}" fullword ascii
    $s6  = "function RgREnFFqomsSEvJRJdsKgN(EDWiuY,QbYLKOwc){return String.fromCharCode(EDWiuY,QbYLKOwc);}" fullword ascii
    $s7  = "function cRvgipuRwdl(fOetbkwDNdNug) {var aQqsHGcI = fcIwxAPIPCkwQtefh.join(WKQHlYCxwrUlAwDj[6]);var BNbSgVewsUzSqqgjpxxXU, yfiyn" ascii
    $s8  = "msXnorB<bOQFpoManw.length;amsXnorB++) {orTNJH+=hEAJua[bOQFpoManw[amsXnorB]];}return orTNJH.substring(3,orTNJH.length);}" fullword ascii
    $s9  = "function sKkCOqcmlmYwvdmlFmG(MwzArcmRYl,uMbKKVwKeGfVHXE,QOziermLQtLuveZKUfvO){return String.fromCharCode(MwzArcmRYl,uMbKKVwKeGfV" ascii
    $s10 = "function XOVlim(){return dbLUgxCgCT(WKQHlYCxwrUlAwDj[12],[0,3,6],WKQHlYCxwrUlAwDj[13]);}" fullword ascii
    $s11 = "function y(uVJhw){return String.fromCharCode(uVJhw);}" fullword ascii
    $s12 = "RgREnFFqomsSEvJRJdsKgN(BNbSgVewsUzSqqgjpxxXU, yfiynjUCBBsvWW);else UotgBBg += sKkCOqcmlmYwvdmlFmG(BNbSgVewsUzSqqgjpxxXU, yfiynjU" ascii
    $s13 = "mCharCode(92)+WKQHlYCxwrUlAwDj[4],true);" fullword ascii
    $s14 = "function VynHTjfBoaeRAYKhlVwiHudW(bKxShtUcurxJtvvZvk,ZzPSlefJfjwLyTQjq){return bKxShtUcurxJtvvZvk.indexOf(ZzPSlefJfjwLyTQjq);}" fullword ascii
    $s15 = "CBBsvWW, YXqZAnfpn);} while (sgGqTOSwcQrElAH < fOetbkwDNdNug.length);return UotgBBg;}" fullword ascii
    $s16 = "var IvTIxUUGRe = aNhWNJdA.createtextfile(KUPFDiTwNo.ExpandEnvironmentStrings(WKQHlYCxwrUlAwDj[2]+WKQHlYCxwrUlAwDj[3])+String.fro" ascii
    $s17 = ";YXqZAnfpn = JvtWjYjIDQWPrHCR & 0xff;if (WquDLtuhAJ == 64) UotgBBg += y(BNbSgVewsUzSqqgjpxxXU);else if (Axiib == 64) UotgBBg += " ascii
    $s18 = "function sKkCOqcmlmYwvdmlFmG(MwzArcmRYl,uMbKKVwKeGfVHXE,QOziermLQtLuveZKUfvO){return String.fromCharCode(MwzArcmRYl,uMbKKVwKeGfV" ascii
    $s19 = "function sNPhzwxsCXUSFU(){return dbLUgxCgCT(WKQHlYCxwrUlAwDj[8],[1,5,7],WKQHlYCxwrUlAwDj[9]);}" fullword ascii
    $s20 = "function dbLUgxCgCT(MPjsZf,bOQFpoManw,fIdDCXxqUF){hEAJua=MPjsZf.split(fIdDCXxqUF);orTNJH = WKQHlYCxwrUlAwDj[14];for(amsXnorB=0;a" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}