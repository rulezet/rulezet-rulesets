rule TTP_XOR_QUAD_CurrentVersionRun_f2e9 {
  strings:
    $key_f2e9 = { a1 86 [2] 85 88 [2] ae a4 [2] 80 86 [2] 94 9d [2] 9b 87 [2] 85 9a [2] 87 9b [2] 9c 9d [2] 80 9a [2] 9c b5 }

  condition:
    any of them
}