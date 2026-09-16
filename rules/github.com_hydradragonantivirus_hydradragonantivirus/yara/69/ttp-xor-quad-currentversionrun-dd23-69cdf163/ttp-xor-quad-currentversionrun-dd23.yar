rule TTP_XOR_QUAD_CurrentVersionRun_dd23 {
  strings:
    $key_dd23 = { 8e 4c [2] aa 42 [2] 81 6e [2] af 4c [2] bb 57 [2] b4 4d [2] aa 50 [2] a8 51 [2] b3 57 [2] af 50 [2] b3 7f }

  condition:
    any of them
}