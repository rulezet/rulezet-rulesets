rule TTP_XOR_QUAD_CurrentVersionRun_c34d {
  strings:
    $key_c34d = { 90 22 [2] b4 2c [2] 9f 00 [2] b1 22 [2] a5 39 [2] aa 23 [2] b4 3e [2] b6 3f [2] ad 39 [2] b1 3e [2] ad 11 }

  condition:
    any of them
}