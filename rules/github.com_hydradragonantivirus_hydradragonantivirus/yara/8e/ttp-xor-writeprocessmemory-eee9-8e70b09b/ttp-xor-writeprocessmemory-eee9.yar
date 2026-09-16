rule TTP_XOR_WriteProcessMemory_eee9 {
  strings:
    $key_eee9 = { b9 9b [2] 8b b9 [2] 8d 8c [2] a3 8c [2] 9c 90 }

  condition:
    any of them
}