rule sig_20170118_595703f7932e768b66f87860db9eba89 {
  meta:
    description = "datamaliciousorder - file 20170118_595703f7932e768b66f87860db9eba89.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "041716d652adc5cce7bf6321b1bbaf4b4296331ad8762b1fc433efe08afef184"

  strings:
    $s1  = "var uvojvotavugetkedasifewpihuwa = [Infinity, \"ne/\"];" fullword ascii
    $s2  = "var ymebzu = [Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, zkenezapukvarovwyxopafakeqj[3], Infinity, In" ascii
    $s3  = "ojvotavugetkedasifewpihuwa[1], Infinity][11];" fullword ascii
    $s4  = "var ifqijywehvikjywgogosobyg = [Infinity, \"cmd\", Infinity, Infinity];" fullword ascii
    $s5  = "var ymebzu = [Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, zkenezapukvarovwyxopafakeqj[3], Infinity, In" ascii
    $s6  = "var tatmejne = [Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, aj" ascii
    $s7  = "var oslogad = [Infinity, abvaxqelysqedoqmuktowizavattagdi[3], Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infini" ascii
    $s8  = "var ijajhahzadjehlobabegukgihgajzyco = [Infinity, \"GET\", Infinity];" fullword ascii
    $s9  = "var ajnofpamledacocoliwholsoggetegu = [Infinity, \"ipt\", Infinity, Infinity];" fullword ascii
    $s10 = "var zkenezapukvarovwyxopafakeqj = [Infinity, Infinity, Infinity, \"ete\", Infinity];" fullword ascii
    $s11 = "var gyfnokysdelfewuhixatluqovci = [Infinity, Infinity, \"Get\", Infinity, Infinity];" fullword ascii
    $s12 = "var byphojyxykuffyjgogegsesgimy = [Infinity, Infinity, \"Get\"];" fullword ascii
    $s13 = "var acwefinf = [Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, uv" ascii
    $s14 = "nofpamledacocoliwholsoggetegu[1], Infinity, Infinity, Infinity, Infinity, Infinity][11];" fullword ascii
    $s15 = "var oslogad = [Infinity, abvaxqelysqedoqmuktowizavattagdi[3], Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infini" ascii
    $s16 = "if ([Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, new Function(quqxy + ywdexy + hivry + ugebmi + orrupyv + qpobuh" ascii
    $s17 = ", Infinity, Infinity, Infinity, Infinity, Infinity][5][elxedxa + olyj + vzyqelgy];" fullword ascii
    $s18 = "var lkyfommi = [kbinovsixzetopuhturhyxsygxiwjixi[0], Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infin" ascii
    $s19 = "var lybde = [Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, Infinity, vohrunefgoflyshibygyjlebu" ascii
    $s20 = "inity, Infinity, baskyvlagcetriligridcomrykexabq[0], Infinity, Infinity, Infinity][13];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}