rule TTP_XOR_QUAD_CurrentVersionRun_c77e {
  strings:
    $key_c77e = { 94 11 [2] b0 1f [2] 9b 33 [2] b5 11 [2] a1 0a [2] ae 10 [2] b0 0d [2] b2 0c [2] a9 0a [2] b5 0d [2] a9 22 }

  condition:
    any of them
}