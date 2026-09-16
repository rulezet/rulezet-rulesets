rule TTP_XOR_QUAD_CurrentVersionRun_dd52 {
  strings:
    $key_dd52 = { 8e 3d [2] aa 33 [2] 81 1f [2] af 3d [2] bb 26 [2] b4 3c [2] aa 21 [2] a8 20 [2] b3 26 [2] af 21 [2] b3 0e }

  condition:
    any of them
}