rule TTP_XOR_QUAD_CurrentVersionRun_dfee {
  strings:
    $key_dfee = { 8c 81 [2] a8 8f [2] 83 a3 [2] ad 81 [2] b9 9a [2] b6 80 [2] a8 9d [2] aa 9c [2] b1 9a [2] ad 9d [2] b1 b2 }

  condition:
    any of them
}