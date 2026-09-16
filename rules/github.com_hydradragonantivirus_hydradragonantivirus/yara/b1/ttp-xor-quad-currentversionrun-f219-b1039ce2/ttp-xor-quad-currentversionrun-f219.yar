rule TTP_XOR_QUAD_CurrentVersionRun_f219 {
  strings:
    $key_f219 = { a1 76 [2] 85 78 [2] ae 54 [2] 80 76 [2] 94 6d [2] 9b 77 [2] 85 6a [2] 87 6b [2] 9c 6d [2] 80 6a [2] 9c 45 }

  condition:
    any of them
}