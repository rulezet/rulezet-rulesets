rule TTP_XOR_QUAD_CurrentVersionRun_fa08 {
  strings:
    $key_fa08 = { a9 67 [2] 8d 69 [2] a6 45 [2] 88 67 [2] 9c 7c [2] 93 66 [2] 8d 7b [2] 8f 7a [2] 94 7c [2] 88 7b [2] 94 54 }

  condition:
    any of them
}