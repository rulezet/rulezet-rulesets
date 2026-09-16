rule TTP_XOR_QUAD_CurrentVersionRun_f508 {
  strings:
    $key_f508 = { a6 67 [2] 82 69 [2] a9 45 [2] 87 67 [2] 93 7c [2] 9c 66 [2] 82 7b [2] 80 7a [2] 9b 7c [2] 87 7b [2] 9b 54 }

  condition:
    any of them
}