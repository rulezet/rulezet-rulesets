rule TTP_XOR_QUAD_CurrentVersionRun_c0eb {
  strings:
    $key_c0eb = { 93 84 [2] b7 8a [2] 9c a6 [2] b2 84 [2] a6 9f [2] a9 85 [2] b7 98 [2] b5 99 [2] ae 9f [2] b2 98 [2] ae b7 }

  condition:
    any of them
}