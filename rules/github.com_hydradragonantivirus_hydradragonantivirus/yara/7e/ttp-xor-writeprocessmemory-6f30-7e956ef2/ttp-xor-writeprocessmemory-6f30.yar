rule TTP_XOR_WriteProcessMemory_6f30 {
  strings:
    $key_6f30 = { 38 42 [2] 0a 60 [2] 0c 55 [2] 22 55 [2] 1d 49 }

  condition:
    any of them
}