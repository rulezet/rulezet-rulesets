rule sig_20151210_78ae22e0c1fc0e2ef6d63ca648b565f1 {
  meta:
    description = "datamaliciousorder - file 20151210_78ae22e0c1fc0e2ef6d63ca648b565f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89ced1ab865726c52ba2055f6fd99065ca2e397779fa1ab0ec537076d725b616"

  strings:
    $s1  = "function owLqSwt(jjvQoomdKWBRniEPGgvEqsZNjsfTMavGjYjq) {return !isNaN(parseFloat(jjvQoomdKWBRniEPGgvEqsZNjsfTMavGjYjq)) && isFin" ascii
    $s2  = "function owLqSwt(jjvQoomdKWBRniEPGgvEqsZNjsfTMavGjYjq) {return !isNaN(parseFloat(jjvQoomdKWBRniEPGgvEqsZNjsfTMavGjYjq)) && isFin" ascii
    $s3  = "function YNRNRHHGvcD(cofqoFmg,bBjjbK){return cofqoFmg.split(bBjjbK)}" fullword ascii
    $s4  = "function bmBZqQkvreisQbSVN(iuSsE){PIcDEESEXqf= '';for(dIwSERLfNiN=(-962+962)/646; dIwSERLfNiN < (1444+138)/791; dIwSERLfNiN++) {" ascii
    $s5  = "function ZSOAsRiFcSfNVHUqYqSTqbhfIJfxNCSjOxpemWDaGLmNXtiHCVWNPb(aXVDRuRAGnVhF,eEuHTWgrHJyOIh){ return LzyoV[MmZTi(aXVDRuRAGnVhF[" ascii
    $s6  = "function ZSOAsRiFcSfNVHUqYqSTqbhfIJfxNCSjOxpemWDaGLmNXtiHCVWNPb(aXVDRuRAGnVhF,eEuHTWgrHJyOIh){ return LzyoV[MmZTi(aXVDRuRAGnVhF[" ascii
    $s7  = "]++;}} return PIcDEESEXqf}" fullword ascii
    $s8  = " HVCyW;}function uOouzjSYEsIbJzc(HinJnVjiyloEGUprs){eval(HinJnVjiyloEGUprs)}" fullword ascii
    $s9  = "MPSEvZDzz[dIwSERLfNiN]=(-644+644)/509; while(true) { if(MPSEvZDzz[dIwSERLfNiN] > iuSsE[dIwSERLfNiN].length-(-221+812)/591) { bre" ascii
    $s10 = "function bmBZqQkvreisQbSVN(iuSsE){PIcDEESEXqf= '';for(dIwSERLfNiN=(-962+962)/646; dIwSERLfNiN < (1444+138)/791; dIwSERLfNiN++) {" ascii
    $s11 = "function MmZTi(MhBoaUTggyw,klxQAmdgArCaq,UkoNLAnT){wyMV=parseInt(MhBoaUTggyw,klxQAmdgArCaq);HVCyW=wyMV.toString(UkoNLAnT);return" ascii
    $s12 = "function MmZTi(MhBoaUTggyw,klxQAmdgArCaq,UkoNLAnT){wyMV=parseInt(MhBoaUTggyw,klxQAmdgArCaq);HVCyW=wyMV.toString(UkoNLAnT);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}