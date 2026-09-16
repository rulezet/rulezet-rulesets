rule TTP_XOR_WriteProcessMemory_2a59 {
  strings:
    $key_2a59 = { 7d 2b [2] 4f 09 [2] 49 3c [2] 67 3c [2] 58 20 }

  condition:
    any of them
}