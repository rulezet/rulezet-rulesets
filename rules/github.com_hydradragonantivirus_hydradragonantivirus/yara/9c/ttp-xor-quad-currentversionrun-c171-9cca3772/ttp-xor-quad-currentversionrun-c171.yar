rule TTP_XOR_QUAD_CurrentVersionRun_c171 {
  strings:
    $key_c171 = { 92 1e [2] b6 10 [2] 9d 3c [2] b3 1e [2] a7 05 [2] a8 1f [2] b6 02 [2] b4 03 [2] af 05 [2] b3 02 [2] af 2d }

  condition:
    any of them
}