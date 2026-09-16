rule TTP_XOR_QUAD_CurrentVersionRun_c728 {
  strings:
    $key_c728 = { 94 47 [2] b0 49 [2] 9b 65 [2] b5 47 [2] a1 5c [2] ae 46 [2] b0 5b [2] b2 5a [2] a9 5c [2] b5 5b [2] a9 74 }

  condition:
    any of them
}