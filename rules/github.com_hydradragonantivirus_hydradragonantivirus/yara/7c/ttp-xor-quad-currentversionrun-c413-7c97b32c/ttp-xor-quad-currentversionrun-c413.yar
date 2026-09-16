rule TTP_XOR_QUAD_CurrentVersionRun_c413 {
  strings:
    $key_c413 = { 97 7c [2] b3 72 [2] 98 5e [2] b6 7c [2] a2 67 [2] ad 7d [2] b3 60 [2] b1 61 [2] aa 67 [2] b6 60 [2] aa 4f }

  condition:
    any of them
}