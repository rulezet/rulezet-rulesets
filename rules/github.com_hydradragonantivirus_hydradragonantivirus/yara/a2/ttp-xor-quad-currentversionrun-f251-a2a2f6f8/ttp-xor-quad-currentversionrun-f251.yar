rule TTP_XOR_QUAD_CurrentVersionRun_f251 {
  strings:
    $key_f251 = { a1 3e [2] 85 30 [2] ae 1c [2] 80 3e [2] 94 25 [2] 9b 3f [2] 85 22 [2] 87 23 [2] 9c 25 [2] 80 22 [2] 9c 0d }

  condition:
    any of them
}