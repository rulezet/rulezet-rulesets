rule TTP_XOR_WriteProcessMemory_fbec {
  strings:
    $key_fbec = { ac 9e [2] 9e bc [2] 98 89 [2] b6 89 [2] 89 95 }

  condition:
    any of them
}