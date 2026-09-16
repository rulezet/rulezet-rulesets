rule TTP_XOR_QUAD_CurrentVersionRun_c02e {
  strings:
    $key_c02e = { 93 41 [2] b7 4f [2] 9c 63 [2] b2 41 [2] a6 5a [2] a9 40 [2] b7 5d [2] b5 5c [2] ae 5a [2] b2 5d [2] ae 72 }

  condition:
    any of them
}