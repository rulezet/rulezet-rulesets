rule TTP_XOR_QUAD_CurrentVersionRun_c03c {
  strings:
    $key_c03c = { 93 53 [2] b7 5d [2] 9c 71 [2] b2 53 [2] a6 48 [2] a9 52 [2] b7 4f [2] b5 4e [2] ae 48 [2] b2 4f [2] ae 60 }

  condition:
    any of them
}