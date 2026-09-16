rule TTP_XOR_QUAD_CurrentVersionRun_d771 {
  strings:
    $key_d771 = { 84 1e [2] a0 10 [2] 8b 3c [2] a5 1e [2] b1 05 [2] be 1f [2] a0 02 [2] a2 03 [2] b9 05 [2] a5 02 [2] b9 2d }

  condition:
    any of them
}