rule TTP_XOR_QUAD_CurrentVersionRun_dff2 {
  strings:
    $key_dff2 = { 8c 9d [2] a8 93 [2] 83 bf [2] ad 9d [2] b9 86 [2] b6 9c [2] a8 81 [2] aa 80 [2] b1 86 [2] ad 81 [2] b1 ae }

  condition:
    any of them
}