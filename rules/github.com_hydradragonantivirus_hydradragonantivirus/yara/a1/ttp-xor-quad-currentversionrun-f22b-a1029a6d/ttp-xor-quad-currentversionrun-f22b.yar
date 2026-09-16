rule TTP_XOR_QUAD_CurrentVersionRun_f22b {
  strings:
    $key_f22b = { a1 44 [2] 85 4a [2] ae 66 [2] 80 44 [2] 94 5f [2] 9b 45 [2] 85 58 [2] 87 59 [2] 9c 5f [2] 80 58 [2] 9c 77 }

  condition:
    any of them
}