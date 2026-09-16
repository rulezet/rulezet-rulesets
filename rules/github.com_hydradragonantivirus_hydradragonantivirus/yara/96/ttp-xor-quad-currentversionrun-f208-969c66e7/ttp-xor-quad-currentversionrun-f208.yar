rule TTP_XOR_QUAD_CurrentVersionRun_f208 {
  strings:
    $key_f208 = { a1 67 [2] 85 69 [2] ae 45 [2] 80 67 [2] 94 7c [2] 9b 66 [2] 85 7b [2] 87 7a [2] 9c 7c [2] 80 7b [2] 9c 54 }

  condition:
    any of them
}