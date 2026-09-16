rule TTP_XOR_QUAD_CurrentVersionRun_c712 {
  strings:
    $key_c712 = { 94 7d [2] b0 73 [2] 9b 5f [2] b5 7d [2] a1 66 [2] ae 7c [2] b0 61 [2] b2 60 [2] a9 66 [2] b5 61 [2] a9 4e }

  condition:
    any of them
}