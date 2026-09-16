rule sig_20160419_0112ad86d1c512421e7e4615f3a21fce {
  meta:
    description = "datamaliciousorder - file 20160419_0112ad86d1c512421e7e4615f3a21fce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51b34cf37bcc09c10bd4418147a0ff2114270549a140422fa47709c2d0d5b128"

  strings:
    $s1  = "return EyVBAOV[0] + EyVBAOV[2] + EyVBAOV[4] + \".F\" + EyVBAOV[7] + EyVBAOV[9] + EyVBAOV[12] + EyVBAOV[14];" fullword ascii
    $s2  = "var OM = true  , KMlB = rOS[7] + rOS[9] + rOS[11];" fullword ascii
    $s3  = "nsXB.open(lWlWl,YVtHO,false);" fullword ascii
    $s4  = "var rOS = (\"2.XMLHTTP oOqPLKE OrFfR XML ream St eesznTFf AD ORckpfA O WJjw D\").split(\" \");" fullword ascii
    $s5  = "return tXgXPuj;" fullword ascii
    $s6  = "function MqAV(ZArDy) {" fullword ascii
    $s7  = "function ZLHd(pqgJJ,nQShR) {" fullword ascii
    $s8  = "eval(function(p,a,c,k,e,d){e=function(c){return c};if(!\"\".replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d" ascii
    $s9  = "return ktkLt;" fullword ascii
    $s10 = "function keMUCxeFK(qKPur) {" fullword ascii
    $s11 = "function IkPM(wTgWH) {" fullword ascii
    $s12 = "return ZumzTK[TRGK[748-748]]=544-544;" fullword ascii
    $s13 = "function KmdiVXjq(rbU) {" fullword ascii
    $s14 = "function nbEqz(EIykdhVd,ztai) {" fullword ascii
    $s15 = "return rbU.size;" fullword ascii
    $s16 = "return xXUWcmI[0];" fullword ascii
    $s17 = "function KULH(kjcqG) {" fullword ascii
    $s18 = "if (C >= ZArDy.length) {break;}" fullword ascii
    $s19 = "function pbITEX(ftCX,XVNEcX) {" fullword ascii
    $s20 = "if (LDoqw != 354-154){return false;} else {return true;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}