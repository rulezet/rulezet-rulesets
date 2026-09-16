rule TTP_XOR_QUAD_CurrentVersionRun_c3f2 {
  strings:
    $key_c3f2 = { 90 9d [2] b4 93 [2] 9f bf [2] b1 9d [2] a5 86 [2] aa 9c [2] b4 81 [2] b6 80 [2] ad 86 [2] b1 81 [2] ad ae }

  condition:
    any of them
}