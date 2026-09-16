rule TTP_XOR_QUAD_CurrentVersionRun_d871 {
  strings:
    $key_d871 = { 8b 1e [2] af 10 [2] 84 3c [2] aa 1e [2] be 05 [2] b1 1f [2] af 02 [2] ad 03 [2] b6 05 [2] aa 02 [2] b6 2d }

  condition:
    any of them
}