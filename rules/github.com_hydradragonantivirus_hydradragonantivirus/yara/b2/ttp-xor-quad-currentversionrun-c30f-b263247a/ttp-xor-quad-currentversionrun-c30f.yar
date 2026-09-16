rule TTP_XOR_QUAD_CurrentVersionRun_c30f {
  strings:
    $key_c30f = { 90 60 [2] b4 6e [2] 9f 42 [2] b1 60 [2] a5 7b [2] aa 61 [2] b4 7c [2] b6 7d [2] ad 7b [2] b1 7c [2] ad 53 }

  condition:
    any of them
}