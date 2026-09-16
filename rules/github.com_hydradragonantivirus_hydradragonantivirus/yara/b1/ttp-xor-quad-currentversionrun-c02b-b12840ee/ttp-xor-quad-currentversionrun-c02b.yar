rule TTP_XOR_QUAD_CurrentVersionRun_c02b {
  strings:
    $key_c02b = { 93 44 [2] b7 4a [2] 9c 66 [2] b2 44 [2] a6 5f [2] a9 45 [2] b7 58 [2] b5 59 [2] ae 5f [2] b2 58 [2] ae 77 }

  condition:
    any of them
}