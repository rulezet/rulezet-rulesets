rule TTP_XOR_QUAD_CurrentVersionRun_f262 {
  strings:
    $key_f262 = { a1 0d [2] 85 03 [2] ae 2f [2] 80 0d [2] 94 16 [2] 9b 0c [2] 85 11 [2] 87 10 [2] 9c 16 [2] 80 11 [2] 9c 3e }

  condition:
    any of them
}