rule TTP_XOR_WriteProcessMemory_d987 {
  strings:
    $key_d987 = { 8e f5 [2] bc d7 [2] ba e2 [2] 94 e2 [2] ab fe }

  condition:
    any of them
}