rule TTP_XOR_QUAD_CurrentVersionRun_dd5c {
  strings:
    $key_dd5c = { 8e 33 [2] aa 3d [2] 81 11 [2] af 33 [2] bb 28 [2] b4 32 [2] aa 2f [2] a8 2e [2] b3 28 [2] af 2f [2] b3 00 }

  condition:
    any of them
}