rule sig_20151216_e3aa4695504e2bb72d4c42d30c55db2f {
  meta:
    description = "datamaliciousorder - file 20151216_e3aa4695504e2bb72d4c42d30c55db2f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9547d1a4ec40639d7cd7659f9a4b22c1870cbccaa605699ad69ebbf27157452f"

  strings:
    $s1  = "function FiJRHPBSPckyyzniB(EdyLl){PtjOLWHXHmv= '';MrLdvjXbBkL=Math.round((Math.pow(Math.sin(289), 2) + Math.pow(Math.cos(289), 2" ascii
    $s2  = "ow(Math.cos(114), 2) - 1)));} DJYdRwLrW[MrLdvjXbBkL]++;}MrLdvjXbBkL++;} return PtjOLWHXHmv}" fullword ascii
    $s3  = "th.pow(Math.cos(250), 2) - 1)); while(true) { if(DJYdRwLrW[MrLdvjXbBkL] > EdyLl[MrLdvjXbBkL].length-(-74+346)/272) { break; } if" ascii
    $s4  = ") - 1));while(true){if (MrLdvjXbBkL >= (1715+991)/451){break;}DJYdRwLrW[MrLdvjXbBkL]=Math.round((Math.pow(Math.sin(250), 2) + Ma" ascii
    $s5  = "function FiJRHPBSPckyyzniB(EdyLl){PtjOLWHXHmv= '';MrLdvjXbBkL=Math.round((Math.pow(Math.sin(289), 2) + Math.pow(Math.cos(289), 2" ascii
    $s6  = "function yPAoorS(jErJjLzWdcVvGzNzgKqJfwnwWranTUKWUlhI) {return !sarGKhiNitp(uRMtgmUCxGalFPk(jErJjLzWdcVvGzNzgKqJfwnwWranTUKWUlhI" ascii
    $s7  = "var c = new Array();c[0]=[];c[0][0]='d';c[0][1]='a';c[0][2]='d';c[0][3]='a';c[0][4]='46';c[0][5]='3d';c[0][6]='42';c[0][7]='14';" ascii
    $s8  = "function VjBeajArnmzfiJrsV(rMAOOswCCS,uVLUgDtdNB) {return parseInt(rMAOOswCCS,uVLUgDtdNB);}" fullword ascii
    $s9  = "k);return iNiEt;}" fullword ascii
    $s10 = "function AoWKl(xHReMlOqFEo,xOPMdleAclnrz,KqohGZgk){TkYT=VjBeajArnmzfiJrsV(xHReMlOqFEo,xOPMdleAclnrz);iNiEt=TkYT.toString(KqohGZg" ascii
    $s11 = "function abWswabFPsEMWtSQsXETDvpDlCShTWuxsxtCShkojpKSXljFJwRpRV(BzsQkpeMljhBQ,xWVabhyRaQMBit){ return CeIcZJA[HIuCpNuB[AoWKl(Bzs" ascii
    $s12 = "function abWswabFPsEMWtSQsXETDvpDlCShTWuxsxtCShkojpKSXljFJwRpRV(BzsQkpeMljhBQ,xWVabhyRaQMBit){ return CeIcZJA[HIuCpNuB[AoWKl(Bzs" ascii
    $s13 = "function AoWKl(xHReMlOqFEo,xOPMdleAclnrz,KqohGZgk){TkYT=VjBeajArnmzfiJrsV(xHReMlOqFEo,xOPMdleAclnrz);iNiEt=TkYT.toString(KqohGZg" ascii
    $s14 = "function ctAUCJPiwMIAvGs(mIziVfZNoTuivMhur,NlUuuPoBxWVrwXDKhSXChpzOCLyTsAgdXQ,tGqczsRKopqLXNLEZvoSkBETQyNqKKuwtQk){eval(mIziVfZN" ascii
    $s15 = "function o(xEtKoDzJzzGp,LoeEplFusNbGdf){xEtKoDzJzzGp.push(LoeEplFusNbGdf);}" fullword ascii
    $s16 = "function EJMyhvNIWaxK(EfKbPPvRybJgT) {return isFinite(EfKbPPvRybJgT);}" fullword ascii
    $s17 = "function sarGKhiNitp(NBKLdYiRkaJYfE) {return isNaN(NBKLdYiRkaJYfE);}" fullword ascii
    $s18 = "function yPAoorS(jErJjLzWdcVvGzNzgKqJfwnwWranTUKWUlhI) {return !sarGKhiNitp(uRMtgmUCxGalFPk(jErJjLzWdcVvGzNzgKqJfwnwWranTUKWUlhI" ascii
    $s19 = "var c = new Array();c[0]=[];c[0][0]='d';c[0][1]='a';c[0][2]='d';c[0][3]='a';c[0][4]='46';c[0][5]='3d';c[0][6]='42';c[0][7]='14';" ascii
    $s20 = "function ctAUCJPiwMIAvGs(mIziVfZNoTuivMhur,NlUuuPoBxWVrwXDKhSXChpzOCLyTsAgdXQ,tGqczsRKopqLXNLEZvoSkBETQyNqKKuwtQk){eval(mIziVfZN" ascii

  condition:
    uint16(0) == 0x4948 and
    8 of them
}