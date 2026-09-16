rule Virus_Infector_Win32_Expiro_Gen_7_25_1 {
   meta:
      description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_25_1.vir"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-03-24"
      hash1 = "5ecbc947f2853fe9a3479e523b5ddfeaec9c2ca98a08e894e9c6652c5132e62e"
   strings:
      $s1 = "                                                                                                                                " ascii
      $s2 = "a+=String[ff](e(v+(z[i]))-12);}};};ps=\"split\";e=(eval);v=\"0x\";a=0;z=\"y\";try{;}catch(zz){a=1}if(!a){try{++e(d)[\"bod\"+z]}c" ascii

      $op0 = { 01 00 30 00 34 00 31 00 39 00 30 00 34 00 42 00 }
      $op1 = { 20 04 35 04 34 04 30 04 3a 04 42 04 3e 04 40 04 }
      $op2 = { f9 73 2c c3 c1 d0 01 33 c7 f5 8b 34 24 58 81 ee }
   condition:
      uint16(0) == 0x5a4d and
      ( all of them and all of ($op*) )
}