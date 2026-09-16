rule TTP_XOR_QUAD_CurrentVersionRun_c05d {
  strings:
    $key_c05d = { 93 32 [2] b7 3c [2] 9c 10 [2] b2 32 [2] a6 29 [2] a9 33 [2] b7 2e [2] b5 2f [2] ae 29 [2] b2 2e [2] ae 01 }

  condition:
    any of them
}