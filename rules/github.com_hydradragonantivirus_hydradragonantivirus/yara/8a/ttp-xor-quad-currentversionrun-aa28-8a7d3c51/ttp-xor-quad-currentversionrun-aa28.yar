rule TTP_XOR_QUAD_CurrentVersionRun_aa28 {
  strings:
    $key_aa28 = { f9 47 [2] dd 49 [2] f6 65 [2] d8 47 [2] cc 5c [2] c3 46 [2] dd 5b [2] df 5a [2] c4 5c [2] d8 5b [2] c4 74 }

  condition:
    any of them
}