rule TTP_XOR_QUAD_CurrentVersionRun_c70e {
  strings:
    $key_c70e = { 94 61 [2] b0 6f [2] 9b 43 [2] b5 61 [2] a1 7a [2] ae 60 [2] b0 7d [2] b2 7c [2] a9 7a [2] b5 7d [2] a9 52 }

  condition:
    any of them
}