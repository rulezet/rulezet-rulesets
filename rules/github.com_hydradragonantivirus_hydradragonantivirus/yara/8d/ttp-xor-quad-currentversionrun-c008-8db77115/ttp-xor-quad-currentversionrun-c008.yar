rule TTP_XOR_QUAD_CurrentVersionRun_c008 {
  strings:
    $key_c008 = { 93 67 [2] b7 69 [2] 9c 45 [2] b2 67 [2] a6 7c [2] a9 66 [2] b7 7b [2] b5 7a [2] ae 7c [2] b2 7b [2] ae 54 }

  condition:
    any of them
}