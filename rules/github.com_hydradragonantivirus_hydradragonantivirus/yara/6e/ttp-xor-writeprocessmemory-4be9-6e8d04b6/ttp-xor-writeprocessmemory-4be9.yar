rule TTP_XOR_WriteProcessMemory_4be9 {
  strings:
    $key_4be9 = { 1c 9b [2] 2e b9 [2] 28 8c [2] 06 8c [2] 39 90 }

  condition:
    any of them
}