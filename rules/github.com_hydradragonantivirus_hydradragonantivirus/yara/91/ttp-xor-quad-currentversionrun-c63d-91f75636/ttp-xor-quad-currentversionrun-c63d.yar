rule TTP_XOR_QUAD_CurrentVersionRun_c63d {
  strings:
    $key_c63d = { 95 52 [2] b1 5c [2] 9a 70 [2] b4 52 [2] a0 49 [2] af 53 [2] b1 4e [2] b3 4f [2] a8 49 [2] b4 4e [2] a8 61 }

  condition:
    any of them
}