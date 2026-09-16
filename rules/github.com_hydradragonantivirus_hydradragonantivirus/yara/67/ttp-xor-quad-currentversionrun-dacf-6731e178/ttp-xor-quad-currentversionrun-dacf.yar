rule TTP_XOR_QUAD_CurrentVersionRun_dacf {
  strings:
    $key_dacf = { 89 a0 [2] ad ae [2] 86 82 [2] a8 a0 [2] bc bb [2] b3 a1 [2] ad bc [2] af bd [2] b4 bb [2] a8 bc [2] b4 93 }

  condition:
    any of them
}