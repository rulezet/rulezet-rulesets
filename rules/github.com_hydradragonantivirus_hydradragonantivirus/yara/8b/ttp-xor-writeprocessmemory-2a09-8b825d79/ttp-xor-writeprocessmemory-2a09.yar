rule TTP_XOR_WriteProcessMemory_2a09 {
  strings:
    $key_2a09 = { 7d 7b [2] 4f 59 [2] 49 6c [2] 67 6c [2] 58 70 }

  condition:
    any of them
}