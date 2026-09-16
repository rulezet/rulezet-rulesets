rule TTP_XOR_WriteProcessMemory_1de9 {
  strings:
    $key_1de9 = { 4a 9b [2] 78 b9 [2] 7e 8c [2] 50 8c [2] 6f 90 }

  condition:
    any of them
}