rule TTP_XOR_QUAD_CurrentVersionRun_c621 {
  strings:
    $key_c621 = { 95 4e [2] b1 40 [2] 9a 6c [2] b4 4e [2] a0 55 [2] af 4f [2] b1 52 [2] b3 53 [2] a8 55 [2] b4 52 [2] a8 7d }

  condition:
    any of them
}