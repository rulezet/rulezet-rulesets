rule TTP_XOR_WriteProcessMemory_6f39 {
  strings:
    $key_6f39 = { 38 4b [2] 0a 69 [2] 0c 5c [2] 22 5c [2] 1d 40 }

  condition:
    any of them
}