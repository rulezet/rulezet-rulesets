rule TTP_XOR_WriteProcessMemory_c987 {
  strings:
    $key_c987 = { 9e f5 [2] ac d7 [2] aa e2 [2] 84 e2 [2] bb fe }

  condition:
    any of them
}