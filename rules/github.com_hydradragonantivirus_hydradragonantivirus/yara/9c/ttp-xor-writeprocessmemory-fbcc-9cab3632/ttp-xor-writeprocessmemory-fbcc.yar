rule TTP_XOR_WriteProcessMemory_fbcc {
  strings:
    $key_fbcc = { ac be [2] 9e 9c [2] 98 a9 [2] b6 a9 [2] 89 b5 }

  condition:
    any of them
}