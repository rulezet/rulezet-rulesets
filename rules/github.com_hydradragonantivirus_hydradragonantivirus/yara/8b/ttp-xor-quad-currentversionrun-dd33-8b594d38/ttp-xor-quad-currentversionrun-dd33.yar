rule TTP_XOR_QUAD_CurrentVersionRun_dd33 {
  strings:
    $key_dd33 = { 8e 5c [2] aa 52 [2] 81 7e [2] af 5c [2] bb 47 [2] b4 5d [2] aa 40 [2] a8 41 [2] b3 47 [2] af 40 [2] b3 6f }

  condition:
    any of them
}