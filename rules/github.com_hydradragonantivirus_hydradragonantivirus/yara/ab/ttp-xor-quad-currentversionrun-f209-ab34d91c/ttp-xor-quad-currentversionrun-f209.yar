rule TTP_XOR_QUAD_CurrentVersionRun_f209 {
  strings:
    $key_f209 = { a1 66 [2] 85 68 [2] ae 44 [2] 80 66 [2] 94 7d [2] 9b 67 [2] 85 7a [2] 87 7b [2] 9c 7d [2] 80 7a [2] 9c 55 }

  condition:
    any of them
}