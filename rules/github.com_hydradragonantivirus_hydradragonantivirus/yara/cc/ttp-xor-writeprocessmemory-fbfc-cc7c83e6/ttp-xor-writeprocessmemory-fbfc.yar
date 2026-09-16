rule TTP_XOR_WriteProcessMemory_fbfc {
  strings:
    $key_fbfc = { ac 8e [2] 9e ac [2] 98 99 [2] b6 99 [2] 89 85 }

  condition:
    any of them
}