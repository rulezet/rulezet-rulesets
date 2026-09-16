rule TTP_XOR_QUAD_CurrentVersionRun_d725 {
  strings:
    $key_d725 = { 84 4a [2] a0 44 [2] 8b 68 [2] a5 4a [2] b1 51 [2] be 4b [2] a0 56 [2] a2 57 [2] b9 51 [2] a5 56 [2] b9 79 }

  condition:
    any of them
}