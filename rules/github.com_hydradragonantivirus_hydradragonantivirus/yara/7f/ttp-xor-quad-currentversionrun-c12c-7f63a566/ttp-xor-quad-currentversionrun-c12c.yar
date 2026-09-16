rule TTP_XOR_QUAD_CurrentVersionRun_c12c {
  strings:
    $key_c12c = { 92 43 [2] b6 4d [2] 9d 61 [2] b3 43 [2] a7 58 [2] a8 42 [2] b6 5f [2] b4 5e [2] af 58 [2] b3 5f [2] af 70 }

  condition:
    any of them
}