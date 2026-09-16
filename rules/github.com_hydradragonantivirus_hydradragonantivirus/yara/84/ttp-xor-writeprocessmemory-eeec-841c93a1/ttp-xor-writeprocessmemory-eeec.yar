rule TTP_XOR_WriteProcessMemory_eeec {
  strings:
    $key_eeec = { b9 9e [2] 8b bc [2] 8d 89 [2] a3 89 [2] 9c 95 }

  condition:
    any of them
}