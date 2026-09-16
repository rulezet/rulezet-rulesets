rule TTP_XOR_QUAD_CurrentVersionRun_c37f {
  strings:
    $key_c37f = { 90 10 [2] b4 1e [2] 9f 32 [2] b1 10 [2] a5 0b [2] aa 11 [2] b4 0c [2] b6 0d [2] ad 0b [2] b1 0c [2] ad 23 }

  condition:
    any of them
}