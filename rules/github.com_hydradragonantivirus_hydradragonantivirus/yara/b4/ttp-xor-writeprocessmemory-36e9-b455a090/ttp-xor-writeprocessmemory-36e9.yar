rule TTP_XOR_WriteProcessMemory_36e9 {
  strings:
    $key_36e9 = { 61 9b [2] 53 b9 [2] 55 8c [2] 7b 8c [2] 44 90 }

  condition:
    any of them
}