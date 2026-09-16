rule TTP_XOR_QUAD_CurrentVersionRun_d6ee {
  strings:
    $key_d6ee = { 85 81 [2] a1 8f [2] 8a a3 [2] a4 81 [2] b0 9a [2] bf 80 [2] a1 9d [2] a3 9c [2] b8 9a [2] a4 9d [2] b8 b2 }

  condition:
    any of them
}