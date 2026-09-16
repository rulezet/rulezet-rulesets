rule TTP_XOR_QUAD_CurrentVersionRun_c019 {
  strings:
    $key_c019 = { 93 76 [2] b7 78 [2] 9c 54 [2] b2 76 [2] a6 6d [2] a9 77 [2] b7 6a [2] b5 6b [2] ae 6d [2] b2 6a [2] ae 45 }

  condition:
    any of them
}