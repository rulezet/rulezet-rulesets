rule TTP_XOR_WriteProcessMemory_5ae9 {
  strings:
    $key_5ae9 = { 0d 9b [2] 3f b9 [2] 39 8c [2] 17 8c [2] 28 90 }

  condition:
    any of them
}