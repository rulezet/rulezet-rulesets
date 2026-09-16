rule TTP_XOR_WriteProcessMemory_fbf3 {
  strings:
    $key_fbf3 = { ac 81 [2] 9e a3 [2] 98 96 [2] b6 96 [2] 89 8a }

  condition:
    any of them
}