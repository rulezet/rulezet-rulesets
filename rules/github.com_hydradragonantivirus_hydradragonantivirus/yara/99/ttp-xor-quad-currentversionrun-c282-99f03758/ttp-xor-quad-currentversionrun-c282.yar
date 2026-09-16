rule TTP_XOR_QUAD_CurrentVersionRun_c282 {
  strings:
    $key_c282 = { 91 ed [2] b5 e3 [2] 9e cf [2] b0 ed [2] a4 f6 [2] ab ec [2] b5 f1 [2] b7 f0 [2] ac f6 [2] b0 f1 [2] ac de }

  condition:
    any of them
}