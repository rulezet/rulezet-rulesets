rule TTP_XOR_QUAD_CurrentVersionRun_d6f2 {
  strings:
    $key_d6f2 = { 85 9d [2] a1 93 [2] 8a bf [2] a4 9d [2] b0 86 [2] bf 9c [2] a1 81 [2] a3 80 [2] b8 86 [2] a4 81 [2] b8 ae }

  condition:
    any of them
}