rule TTP_XOR_WriteProcessMemory_fbee {
  strings:
    $key_fbee = { ac 9c [2] 9e be [2] 98 8b [2] b6 8b [2] 89 97 }

  condition:
    any of them
}