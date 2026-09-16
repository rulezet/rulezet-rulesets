rule TTP_XOR_QUAD_CurrentVersionRun_c03a {
  strings:
    $key_c03a = { 93 55 [2] b7 5b [2] 9c 77 [2] b2 55 [2] a6 4e [2] a9 54 [2] b7 49 [2] b5 48 [2] ae 4e [2] b2 49 [2] ae 66 }

  condition:
    any of them
}