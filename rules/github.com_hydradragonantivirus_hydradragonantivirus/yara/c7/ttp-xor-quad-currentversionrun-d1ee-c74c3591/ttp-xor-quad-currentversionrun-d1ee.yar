rule TTP_XOR_QUAD_CurrentVersionRun_d1ee {
  strings:
    $key_d1ee = { 82 81 [2] a6 8f [2] 8d a3 [2] a3 81 [2] b7 9a [2] b8 80 [2] a6 9d [2] a4 9c [2] bf 9a [2] a3 9d [2] bf b2 }

  condition:
    any of them
}