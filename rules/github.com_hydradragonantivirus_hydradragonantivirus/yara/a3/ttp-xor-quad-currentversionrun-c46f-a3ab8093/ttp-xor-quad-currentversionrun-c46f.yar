rule TTP_XOR_QUAD_CurrentVersionRun_c46f {
  strings:
    $key_c46f = { 97 00 [2] b3 0e [2] 98 22 [2] b6 00 [2] a2 1b [2] ad 01 [2] b3 1c [2] b1 1d [2] aa 1b [2] b6 1c [2] aa 33 }

  condition:
    any of them
}