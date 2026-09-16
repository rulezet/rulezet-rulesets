rule TTP_XOR_WriteProcessMemory_6eec {
  strings:
    $key_6eec = { 39 9e [2] 0b bc [2] 0d 89 [2] 23 89 [2] 1c 95 }

  condition:
    any of them
}