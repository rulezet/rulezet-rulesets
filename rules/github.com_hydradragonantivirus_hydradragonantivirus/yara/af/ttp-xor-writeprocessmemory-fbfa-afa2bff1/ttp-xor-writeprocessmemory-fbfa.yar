rule TTP_XOR_WriteProcessMemory_fbfa {
  strings:
    $key_fbfa = { ac 88 [2] 9e aa [2] 98 9f [2] b6 9f [2] 89 83 }

  condition:
    any of them
}