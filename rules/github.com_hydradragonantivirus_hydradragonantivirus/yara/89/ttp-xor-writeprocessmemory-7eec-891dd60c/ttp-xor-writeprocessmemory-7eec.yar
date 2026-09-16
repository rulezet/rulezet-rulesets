rule TTP_XOR_WriteProcessMemory_7eec {
  strings:
    $key_7eec = { 29 9e [2] 1b bc [2] 1d 89 [2] 33 89 [2] 0c 95 }

  condition:
    any of them
}