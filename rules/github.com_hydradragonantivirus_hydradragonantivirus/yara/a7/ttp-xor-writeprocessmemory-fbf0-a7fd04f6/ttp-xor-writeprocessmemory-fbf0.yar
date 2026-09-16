rule TTP_XOR_WriteProcessMemory_fbf0 {
  strings:
    $key_fbf0 = { ac 82 [2] 9e a0 [2] 98 95 [2] b6 95 [2] 89 89 }

  condition:
    any of them
}