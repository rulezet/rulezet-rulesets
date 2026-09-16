rule TTP_XOR_QUAD_CurrentVersionRun_dfef {
  strings:
    $key_dfef = { 8c 80 [2] a8 8e [2] 83 a2 [2] ad 80 [2] b9 9b [2] b6 81 [2] a8 9c [2] aa 9d [2] b1 9b [2] ad 9c [2] b1 b3 }

  condition:
    any of them
}