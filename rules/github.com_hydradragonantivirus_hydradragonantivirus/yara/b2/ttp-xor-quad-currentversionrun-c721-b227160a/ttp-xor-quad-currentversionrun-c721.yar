rule TTP_XOR_QUAD_CurrentVersionRun_c721 {
  strings:
    $key_c721 = { 94 4e [2] b0 40 [2] 9b 6c [2] b5 4e [2] a1 55 [2] ae 4f [2] b0 52 [2] b2 53 [2] a9 55 [2] b5 52 [2] a9 7d }

  condition:
    any of them
}