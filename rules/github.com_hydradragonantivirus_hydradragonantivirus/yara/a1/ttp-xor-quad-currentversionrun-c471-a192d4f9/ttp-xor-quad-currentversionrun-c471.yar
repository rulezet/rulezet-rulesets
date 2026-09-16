rule TTP_XOR_QUAD_CurrentVersionRun_c471 {
  strings:
    $key_c471 = { 97 1e [2] b3 10 [2] 98 3c [2] b6 1e [2] a2 05 [2] ad 1f [2] b3 02 [2] b1 03 [2] aa 05 [2] b6 02 [2] aa 2d }

  condition:
    any of them
}