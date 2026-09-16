rule TTP_XOR_QUAD_CurrentVersionRun_aa17 {
  strings:
    $key_aa17 = { f9 78 [2] dd 76 [2] f6 5a [2] d8 78 [2] cc 63 [2] c3 79 [2] dd 64 [2] df 65 [2] c4 63 [2] d8 64 [2] c4 4b }

  condition:
    any of them
}