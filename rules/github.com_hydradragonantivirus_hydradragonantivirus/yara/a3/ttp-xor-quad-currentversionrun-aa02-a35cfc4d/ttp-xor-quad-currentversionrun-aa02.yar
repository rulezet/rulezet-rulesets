rule TTP_XOR_QUAD_CurrentVersionRun_aa02 {
  strings:
    $key_aa02 = { f9 6d [2] dd 63 [2] f6 4f [2] d8 6d [2] cc 76 [2] c3 6c [2] dd 71 [2] df 70 [2] c4 76 [2] d8 71 [2] c4 5e }

  condition:
    any of them
}