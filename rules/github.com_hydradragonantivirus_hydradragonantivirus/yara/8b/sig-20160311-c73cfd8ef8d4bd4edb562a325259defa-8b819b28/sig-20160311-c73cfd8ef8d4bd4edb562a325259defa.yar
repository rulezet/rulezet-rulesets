rule sig_20160311_c73cfd8ef8d4bd4edb562a325259defa {
  meta:
    description = "datamaliciousorder - file 20160311_c73cfd8ef8d4bd4edb562a325259defa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "10037d2a0b52d3f593caab32590a14ffe87190e2dbbfde1317f0f25fb00d4101"

  strings:
    $s1  = "soFar[tr + \"p\" + unwrap](\"GE\" + seekingTransport, \"htt\".pipe() + setMatched + \"alit-\" + rootjQuery + \".co.il\" + getAll" ascii
    $s2  = "soFar[tr + \"p\" + unwrap](\"GE\" + seekingTransport, \"htt\".pipe() + setMatched + \"alit-\" + rootjQuery + \".co.il\" + getAll" ascii
    $s3  = "using = ((Math.pow((1 * self), (1 * contextBackup)) - (Math.pow(77, contextBackup) - 5847)), ((close + 1) & (push | 13)), eval(" ascii
    $s4  = "opt[rheader + \"n\"](checkOn.pipe(((9 * createButtonPseudo + 8))), (optionSet / 45), ((outerCache + 1), (after | 68), (value - 1" ascii
    $s5  = "opt[rheader + \"n\"](checkOn.pipe(((9 * createButtonPseudo + 8))), (optionSet / 45), ((outerCache + 1), (after | 68), (value - 1" ascii
    $s6  = "rhtml[\"saveT\".pipe() + identifier](checkOn, 2);" fullword ascii
    $s7  = "using = ((Math.pow((1 * self), (1 * contextBackup)) - (Math.pow(77, contextBackup) - 5847)), ((close + 1) & (push | 13)), eval(" ascii
    $s8  = "ipe() + returnValue, !(self == (((((3102 / styles), (36 * win + 15), (Math.pow(indirect, 2) - show), 1) & ((open | 227), (groups" ascii
    $s9  = "rhtml = using[dataPriv + \"t\".pipe()][props + \"ate\" + b](\"ADOD\" + rfocusable + \"ream\".pipe());" fullword ascii
    $s10 = "soFar = using[\"WScrip\" + udataOld][\"Creat\".pipe() + Deferred + \"ect\"](cors + \"2.XM\" + unit + \"TP\".pipe());" fullword ascii
    $s11 = "th\" + bool + \"s\".pipe()));" fullword ascii
    $s12 = "each = guid[propName + \"Obje\" + not](\"WSc\".pipe() + fixInput + \"hell\");" fullword ascii
    $s13 = "rootjQuery = \"law\", dataShow = 61, postSelector = 14756, close = 11, tr = \"o\";" fullword ascii
    $s14 = "checkOn = each[toArray + \"Envi\" + callback + \"mentSt\".pipe() + createCache + \"gs\"](send + \"P%/\") + insertBefore + \"Clas" ascii
    $s15 = "checkOn = each[toArray + \"Envi\" + callback + \"mentSt\".pipe() + createCache + \"gs\"](send + \"P%/\") + insertBefore + \"Clas" ascii
    $s16 = "var subordinate = (function String.prototype.pipe() {" fullword ascii
    $s17 = " + subordinate + \"c\" + traditional;" fullword ascii
    $s18 = "soFar[\"se\" + ret + \"d\"]();" fullword ascii
    $s19 = "rhtml[tr + \"p\" + unwrap]();" fullword ascii
    $s20 = "identifier = \"oFile\";" fullword ascii

  condition:
    uint16(0) == 0x706f and
    8 of them
}