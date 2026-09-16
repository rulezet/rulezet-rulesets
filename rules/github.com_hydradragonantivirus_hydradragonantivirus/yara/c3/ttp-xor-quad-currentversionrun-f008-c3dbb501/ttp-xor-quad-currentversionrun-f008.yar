rule TTP_XOR_QUAD_CurrentVersionRun_f008 {
  strings:
    $key_f008 = { a3 67 [2] 87 69 [2] ac 45 [2] 82 67 [2] 96 7c [2] 99 66 [2] 87 7b [2] 85 7a [2] 9e 7c [2] 82 7b [2] 9e 54 }

  condition:
    any of them
}