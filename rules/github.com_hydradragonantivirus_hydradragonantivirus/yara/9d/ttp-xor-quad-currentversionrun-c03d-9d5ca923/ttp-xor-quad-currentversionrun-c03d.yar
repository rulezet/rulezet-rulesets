rule TTP_XOR_QUAD_CurrentVersionRun_c03d {
  strings:
    $key_c03d = { 93 52 [2] b7 5c [2] 9c 70 [2] b2 52 [2] a6 49 [2] a9 53 [2] b7 4e [2] b5 4f [2] ae 49 [2] b2 4e [2] ae 61 }

  condition:
    any of them
}