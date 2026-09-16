rule TTP_XOR_WriteProcessMemory_fbcd {
  strings:
    $key_fbcd = { ac bf [2] 9e 9d [2] 98 a8 [2] b6 a8 [2] 89 b4 }

  condition:
    any of them
}