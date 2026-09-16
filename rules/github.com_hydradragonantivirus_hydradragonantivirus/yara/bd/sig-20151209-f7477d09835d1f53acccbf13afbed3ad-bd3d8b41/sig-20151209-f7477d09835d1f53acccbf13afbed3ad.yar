rule sig_20151209_f7477d09835d1f53acccbf13afbed3ad {
  meta:
    description = "datamaliciousorder - file 20151209_f7477d09835d1f53acccbf13afbed3ad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7d45f9d1d2391898968d20c0623f34bf0529d6f6042450f8fdb123b6360c72e"

  strings:
    $s1  = "function BKFvJiF(xAVcsiUemeBIwFPNIGGpYWegcOzxVCHlxzDc) {return !isNaN(parseFloat(xAVcsiUemeBIwFPNIGGpYWegcOzxVCHlxzDc)) && isFin" ascii
    $s2  = "function BKFvJiF(xAVcsiUemeBIwFPNIGGpYWegcOzxVCHlxzDc) {return !isNaN(parseFloat(xAVcsiUemeBIwFPNIGGpYWegcOzxVCHlxzDc)) && isFin" ascii
    $s3  = "function LoQkqqTAqGzmUyLWT(crwrE){AofcRwOhPuJ= '';for(SqJmJxaxzyY=(-244+244)/570; SqJmJxaxzyY < (1361+115)/738; SqJmJxaxzyY++) {" ascii
    $s4  = "function SEuLG(xWwIpKNqqrx,lDUxqTlZOGzSG,nDqZFWRP){aMUo=parseInt(xWwIpKNqqrx,lDUxqTlZOGzSG);cfStZ=aMUo.toString(nDqZFWRP);return" ascii
    $s5  = " cfStZ;}function QqEFjQvVyOIQIum(juqbAUiwWIeVOuKRl){eval(juqbAUiwWIeVOuKRl)}" fullword ascii
    $s6  = "function LoQkqqTAqGzmUyLWT(crwrE){AofcRwOhPuJ= '';for(SqJmJxaxzyY=(-244+244)/570; SqJmJxaxzyY < (1361+115)/738; SqJmJxaxzyY++) {" ascii
    $s7  = "} return AofcRwOhPuJ}" fullword ascii
    $s8  = "function SEuLG(xWwIpKNqqrx,lDUxqTlZOGzSG,nDqZFWRP){aMUo=parseInt(xWwIpKNqqrx,lDUxqTlZOGzSG);cfStZ=aMUo.toString(nDqZFWRP);return" ascii
    $s9  = "function nfTQuIXNikYcxdOmzprYInOtceNqqeftjFitBzRcGeNWqMyOXxyYdL(PYIRMcucmQdti,gTkroBdklZCvTK){ return JiWyh[SEuLG(PYIRMcucmQdti[" ascii
    $s10 = "BFBIVczmu[SqJmJxaxzyY]=(-80+80)/551; while(true) { if(BFBIVczmu[SqJmJxaxzyY] > crwrE[SqJmJxaxzyY].length-(342+644)/986) { break;" ascii
    $s11 = "function qTfGogIRKGY(yvtjeLtO,CwvEXU){return yvtjeLtO.split(CwvEXU)}" fullword ascii
    $s12 = "function nfTQuIXNikYcxdOmzprYInOtceNqqeftjFitBzRcGeNWqMyOXxyYdL(PYIRMcucmQdti,gTkroBdklZCvTK){ return JiWyh[SEuLG(PYIRMcucmQdti[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}