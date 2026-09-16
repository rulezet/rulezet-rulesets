rule TTP_XOR_QUAD_CurrentVersionRun_c07e {
  strings:
    $key_c07e = { 93 11 [2] b7 1f [2] 9c 33 [2] b2 11 [2] a6 0a [2] a9 10 [2] b7 0d [2] b5 0c [2] ae 0a [2] b2 0d [2] ae 22 }

  condition:
    any of them
}