rule sig_20160118_faf3d13ad254cbff4890e755974c0322 {
  meta:
    description = "datamaliciousorder - file 20160118_faf3d13ad254cbff4890e755974c0322.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "619dd1c4fc0d838c0caeb25bfa7e57b68ed4270dd88fcfe143072cf669d731a6"

  strings:
    $x1 = "var a0='555C565E0D0A020B24060108130B0B000A1D4A070B095E3C5E070D100D1E010A4A070B094A0C0F5E17555E55505157555050535C505E55',t1='e '," ascii
    $s2 = "t ',=' t',='ng.',='%USER',='.co',='Send ',=' mak',='ct(',='\"\", ',='r \"+',='.wmv',='File(',='.C',='} ',='\"+',='rn',='.txt\"'," ascii
    $s3 = "true)'+w1+o0+'(v'+'ar i'+b4++++'fp.W'+k4+h6+'e(\"d'+++'\"+cq'+'+S'+'trin'+'g.'+'from'+y6+'Code('+'i)+\":'+'\"+'+'cs+c'+'q+\" '++" ascii
    $s4 = "S',p7='te',q1='in',k8='t.Cr',s1='*.r',o6='s+\"Ru',y0='me f',=' o',='lda',=' (xo.',='i<=90',='cript',='can h',='doc',=' wall',='e" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and all of them
}