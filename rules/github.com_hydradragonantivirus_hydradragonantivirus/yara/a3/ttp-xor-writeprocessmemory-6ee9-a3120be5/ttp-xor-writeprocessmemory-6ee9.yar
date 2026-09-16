rule TTP_XOR_WriteProcessMemory_6ee9 {
  strings:
    $key_6ee9 = { 39 9b [2] 0b b9 [2] 0d 8c [2] 23 8c [2] 1c 90 }

  condition:
    any of them
}