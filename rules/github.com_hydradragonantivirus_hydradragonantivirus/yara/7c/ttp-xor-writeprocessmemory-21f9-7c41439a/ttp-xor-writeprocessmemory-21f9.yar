rule TTP_XOR_WriteProcessMemory_21f9 {
  strings:
    $key_21f9 = { 76 8b [2] 44 a9 [2] 42 9c [2] 6c 9c [2] 53 80 }

  condition:
    any of them
}