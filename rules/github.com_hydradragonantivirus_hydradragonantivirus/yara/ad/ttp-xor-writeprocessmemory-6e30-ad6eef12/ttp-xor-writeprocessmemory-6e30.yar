rule TTP_XOR_WriteProcessMemory_6e30 {
  strings:
    $key_6e30 = { 39 42 [2] 0b 60 [2] 0d 55 [2] 23 55 [2] 1c 49 }

  condition:
    any of them
}