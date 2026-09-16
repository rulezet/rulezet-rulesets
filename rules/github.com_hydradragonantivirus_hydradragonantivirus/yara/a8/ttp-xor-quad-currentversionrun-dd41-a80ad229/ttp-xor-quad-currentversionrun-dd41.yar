rule TTP_XOR_QUAD_CurrentVersionRun_dd41 {
  strings:
    $key_dd41 = { 8e 2e [2] aa 20 [2] 81 0c [2] af 2e [2] bb 35 [2] b4 2f [2] aa 32 [2] a8 33 [2] b3 35 [2] af 32 [2] b3 1d }

  condition:
    any of them
}