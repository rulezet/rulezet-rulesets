rule TTP_XOR_QUAD_CurrentVersionRun_dd51 {
  strings:
    $key_dd51 = { 8e 3e [2] aa 30 [2] 81 1c [2] af 3e [2] bb 25 [2] b4 3f [2] aa 22 [2] a8 23 [2] b3 25 [2] af 22 [2] b3 0d }

  condition:
    any of them
}