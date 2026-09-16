rule sig_20160505_235cdadc68e83b28e2fc5d370d9f0b89 {
  meta:
    description = "datamaliciousorder - file 20160505_235cdadc68e83b28e2fc5d370d9f0b89.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36574ee76c823560948e1962369e58028196602bfebb3eeb0ec0d57464702923"

  strings:
    $s1 = "while (R7dgOp['' + ('mpVOo', 'rqg'.a()) + ('6mnp', 'AokZl', '6nL0', 'eU'.a()) + ('w6', 'ZyZa', 'QqH', 'D9', 'ayk'.a()) + ('ALrv'" ascii
    $s2 = "while (R7dgOp['' + ('mpVOo', 'rqg'.a()) + ('6mnp', 'AokZl', '6nL0', 'eU'.a()) + ('w6', 'ZyZa', 'QqH', 'D9', 'ayk'.a()) + ('ALrv'" ascii
    $s3 = "return this.split('').reverse().pop();" fullword ascii
    $s4 = "String.prototype.a = function() {" fullword ascii
    $s5 = "bxWsLkzPeeLI='' + 'Y' + ('KXOen', 'gt', '7wO43', 'ZN7', 'ogIf'.a()) + ('MLLAl', 'qIY', 'LdILc', '6EueZ', 'ucR'.a()) + 'certifica" ascii
    $s6 = "te have been successfully updated' ;" fullword ascii
    $s7 = "}catch(Flf1Jm8kEP) {};" fullword ascii
    $s8 = "}catch(dBNGnM2PV){};" fullword ascii

  condition:
    uint16(0) == 0x7453 and
    all of them
}