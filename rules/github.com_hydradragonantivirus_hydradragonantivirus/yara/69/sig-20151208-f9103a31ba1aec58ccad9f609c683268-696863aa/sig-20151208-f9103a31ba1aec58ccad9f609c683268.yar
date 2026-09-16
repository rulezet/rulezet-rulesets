rule sig_20151208_f9103a31ba1aec58ccad9f609c683268 {
  meta:
    description = "datamaliciousorder - file 20151208_f9103a31ba1aec58ccad9f609c683268.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9757d8cb2c3d20c7523654475965b6f03eb4cb0fc94730ec88617b528a64f9b7"

  strings:
    $s1  = "function nzFqmou(NSDxskoIreeSIrdBhxOlDfSYEXjHrPdxXKMx) {return !isNaN(parseFloat(NSDxskoIreeSIrdBhxOlDfSYEXjHrPdxXKMx)) && isFin" ascii
    $s2  = "function nzFqmou(NSDxskoIreeSIrdBhxOlDfSYEXjHrPdxXKMx) {return !isNaN(parseFloat(NSDxskoIreeSIrdBhxOlDfSYEXjHrPdxXKMx)) && isFin" ascii
    $s3  = "var wLxAgplINKcXJ=[];for(qjqnUiZ=(-538+538)/869;qjqnUiZ<(36130+222)/284;qjqnUiZ++){wLxAgplINKcXJ[qjqnUiZ]=String.fromCharCode(qj" ascii
    $s4  = "push(\"32\");y.push(\"13\");y.push(\"10\");y.push(\"9\");y.push(\"105\");y.push(\"102\");y.push(\"32\");y.push(\"40\");y.push(\"" ascii
    $s5  = "push(\"32\");N.push(\"61\");N.push(\"32\");N.push(\"34\");N.push(\"50\");N.push(\"46\");N.push(\"88\");N.push(\"77\");N.push(\"7" ascii
    $s6  = "function rqvJOikINdw(FfSFMcmh,gHbdQm){return FfSFMcmh.split(gHbdQm)}" fullword ascii
    $s7  = ";}} return MKXpFqAQIQf}" fullword ascii
    $s8  = "push(\"104\");y.push(\"115\");y.push(\"41\");y.push(\"32\");y.push(\"32\");y.push(\"123\");y.push(\"32\");y.push(\"13\");y.push(" ascii
    $s9  = "push(\"97\");N.push(\"114\");N.push(\"32\");N.push(\"122\");N.push(\"88\");N.push(\"32\");N.push(\"61\");N.push(\"32\");N.push(" ascii
    $s10 = "function jspeUpTbdgRMFJKLbsewpXXEZfxvXxKTEtjoKvntOXOseeeTIdHHBj(zmOQSzqVMUMAN,FuonOoXnMqmwmC){ return wLxAgplINKcXJ[rDSdL(zmOQSz" ascii
    $s11 = ";return paumC;}function dkmFFKJOTRrEEhX(vgKsvNCqWzCNIFRXE){eval(vgKsvNCqWzCNIFRXE)}" fullword ascii
    $s12 = "push(\"42\");y.push(\"69\");y.push(\"111\");y.push(\"98\");y.push(\"113\");y.push(\"56\");y.push(\"51\");y.push(\"56\");y.push(" ascii
    $s13 = "push(\"32\");y.push(\"50\");y.push(\"56\");y.push(\"52\");y.push(\"56\");y.push(\"45\");y.push(\"57\");y.push(\"53\");y.push(\"5" ascii
    $s14 = "push(\"46\");y.push(\"115\");y.push(\"101\");y.push(\"110\");y.push(\"100\");y.push(\"40\");y.push(\"41\");y.push(\"59\");y.push" ascii
    $s15 = "push(\"59\");N.push(\"13\");N.push(\"10\");N.push(\"118\");N.push(\"97\");N.push(\"114\");N.push(\"32\");N.push(\"66\");N.push(" ascii
    $s16 = "push(\"117\");y.push(\"111\");y.push(\"102\");y.push(\"73\");y.push(\"84\");y.push(\"86\");y.push(\"120\");y.push(\"43\");y.push" ascii
    $s17 = "push(\"88\");y.push(\"79\");y.push(\"49\");y.push(\"50\");y.push(\"72\");y.push(\"111\");y.push(\"88\");y.push(\"121\");y.push(" ascii
    $s18 = "push(\"59\");N.push(\"13\");N.push(\"10\");N.push(\"118\");N.push(\"97\");N.push(\"114\");N.push(\"32\");N.push(\"104\");N.push(" ascii
    $s19 = "push(\"92\");N.push(\"92\");N.push(\"34\");N.push(\"59\");N.push(\"13\");N.push(\"10\");N.push(\"118\");N.push(\"97\");N.push(\"" ascii
    $s20 = "qnUiZ)}function rDSdL(QykWVziNHcN,RLNeEEwGMPbwq,QQhBdiZE){tnBQ=parseInt(QykWVziNHcN,RLNeEEwGMPbwq);paumC=tnBQ.toString(QQhBdiZE)" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}