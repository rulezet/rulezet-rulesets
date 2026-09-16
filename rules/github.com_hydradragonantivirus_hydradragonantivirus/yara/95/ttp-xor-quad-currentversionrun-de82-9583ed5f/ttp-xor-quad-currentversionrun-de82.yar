rule TTP_XOR_QUAD_CurrentVersionRun_de82 {
  strings:
    $key_de82 = { 8d ed [2] a9 e3 [2] 82 cf [2] ac ed [2] b8 f6 [2] b7 ec [2] a9 f1 [2] ab f0 [2] b0 f6 [2] ac f1 [2] b0 de }

  condition:
    any of them
}