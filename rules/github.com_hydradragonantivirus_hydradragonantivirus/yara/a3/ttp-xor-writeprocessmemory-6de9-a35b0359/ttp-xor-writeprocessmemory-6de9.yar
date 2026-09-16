rule TTP_XOR_WriteProcessMemory_6de9 {
  strings:
    $key_6de9 = { 3a 9b [2] 08 b9 [2] 0e 8c [2] 20 8c [2] 1f 90 }

  condition:
    any of them
}