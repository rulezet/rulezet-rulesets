rule TTP_XOR_WriteProcessMemory_36f9 {
  strings:
    $key_36f9 = { 61 8b [2] 53 a9 [2] 55 9c [2] 7b 9c [2] 44 80 }

  condition:
    any of them
}