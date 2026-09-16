rule TTP_XOR_WriteProcessMemory_4aec {
  strings:
    $key_4aec = { 1d 9e [2] 2f bc [2] 29 89 [2] 07 89 [2] 38 95 }

  condition:
    any of them
}