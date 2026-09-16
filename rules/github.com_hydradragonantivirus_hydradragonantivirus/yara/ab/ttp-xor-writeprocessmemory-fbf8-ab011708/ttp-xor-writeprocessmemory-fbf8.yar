rule TTP_XOR_WriteProcessMemory_fbf8 {
  strings:
    $key_fbf8 = { ac 8a [2] 9e a8 [2] 98 9d [2] b6 9d [2] 89 81 }

  condition:
    any of them
}