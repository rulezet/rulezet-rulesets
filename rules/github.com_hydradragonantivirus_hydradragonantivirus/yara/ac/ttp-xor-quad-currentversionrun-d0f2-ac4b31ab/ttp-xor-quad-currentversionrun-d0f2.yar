rule TTP_XOR_QUAD_CurrentVersionRun_d0f2 {
  strings:
    $key_d0f2 = { 83 9d [2] a7 93 [2] 8c bf [2] a2 9d [2] b6 86 [2] b9 9c [2] a7 81 [2] a5 80 [2] be 86 [2] a2 81 [2] be ae }

  condition:
    any of them
}