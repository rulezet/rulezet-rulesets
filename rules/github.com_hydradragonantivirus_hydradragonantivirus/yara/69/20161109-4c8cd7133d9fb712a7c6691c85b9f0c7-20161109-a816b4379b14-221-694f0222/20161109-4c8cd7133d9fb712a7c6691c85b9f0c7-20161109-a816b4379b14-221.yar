rule _20161109_4c8cd7133d9fb712a7c6691c85b9f0c7_20161109_a816b4379b14_221 {
  meta:
    description = "datamaliciousorder - from files 20161109_4c8cd7133d9fb712a7c6691c85b9f0c7.js, 20161109_a816b4379b14350097189acc028342b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f8018cae65263d7a37b11d66903d1bca52482e47867ea72e375ef388e80594f"
    hash2       = "3f6ddfca52cc0e02bd7e183c06cad2ad16686eb9edefc5f15a932c5b5369a722"

  strings:
    $s1  = "var TROLLOLOLOLO500 = new Function(\"JeronimootomatoesFROG2_a5,JeronimootomatoesFROG2HORDA5\", 'return JeronimootomatoesFROG2_bC" ascii
    $s2  = "JeronimootomatoesFROG2undefilled.angle = function(JeronimootomatoesFROG2p) {" fullword ascii
    $s3  = "JeronimootomatoesFROG2Native.JeronimootomatoesFROG2typize=function(a,b){a.type||(a.type=function(a){return JeronimootomatoesFROG" ascii
    $s4  = "JeronimootomatoesFROG2undefilled.JeronimootomatoesFROG2sameOrN = function(JeronimootomatoesFROG2param1, JeronimootomatoesFROG2pa" ascii
    $s5  = "JeronimootomatoesFROG2Native.JeronimootomatoesFROG2typize=function(a,b){a.type||(a.type=function(a){return JeronimootomatoesFROG" ascii
    $s6  = "JeronimootomatoesFROG2undefilled.JeronimootomatoesFROG2sameOrN = function(JeronimootomatoesFROG2param1, JeronimootomatoesFROG2pa" ascii
    $s7  = "JeronimootomatoesFROG2undefilled.dEDWWEE = function(){" fullword ascii
    $s8  = "        } while (JeronimootomatoesFROG2XCOP < JeronimootomatoesFROG2len && JeronimootomatoesFROG2c4 == -1);" fullword ascii
    $s9  = "        } while (JeronimootomatoesFROG2XCOP < JeronimootomatoesFROG2len && JeronimootomatoesFROG2ddDccC1 == -1);" fullword ascii
    $s10 = "        } while (JeronimootomatoesFROG2XCOP < JeronimootomatoesFROG2len && JeronimootomatoesFROG2c3 == -1);" fullword ascii
    $s11 = "function JeronimootomatoesFROG_OOO_OOO(TT){" fullword ascii
    $s12 = "function JeronimootomatoesFROG2sud(vardos){" fullword ascii
    $s13 = "function JeronimootomatoesFROG2_bCho(T, D, C) {" fullword ascii
    $s14 = "function JeronimootomatoesFROG2undefilled(velVLUMAHx, velVLUMAHy) {" fullword ascii
    $s15 = "function JeronimootomatoesFROG2_a2(JeronimootomatoesFROG2gutter, JeronimootomatoesFROG2StrokaParam2) {" fullword ascii
    $s16 = "if (JeronimootomatoesFROG2FrankSinatra[0]!= 77 || JeronimootomatoesFROG2FrankSinatra[1]!= 90)return false;" fullword ascii
    $s17 = "function JeronimootomatoesFROG2_cCho(a,b,c,d){a[b](c,d)}" fullword ascii
    $s18 = "JeronimootomatoesFROG2rampart[JeronimootomatoesFROG2promises ]((JeronimootomatoesFROG2StrokaParam2,\"ru\") +\"\"+Jeronimootomato" ascii
    $s19 = "};JeronimootomatoesFROG2Native.JeronimootomatoesFROG2XCOPmplement = function(JeronimootomatoesFROG2objects, JeronimootomatoesFRO" ascii
    $s20 = "var JeronimootomatoesFROG2dodo = false;" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (8 of them)
    ) or (all of them)
}