rule TTP_XOR_WriteProcessMemory_3be9 {
  strings:
    $key_3be9 = { 6c 9b [2] 5e b9 [2] 58 8c [2] 76 8c [2] 49 90 }

  condition:
    any of them
}