rule TTP_XOR_WriteProcessMemory_ecf9 {
  strings:
    $key_ecf9 = { bb 8b [2] 89 a9 [2] 8f 9c [2] a1 9c [2] 9e 80 }

  condition:
    any of them
}