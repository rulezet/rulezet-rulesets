rule TTP_XOR_WriteProcessMemory_2a0c {
  strings:
    $key_2a0c = { 7d 7e [2] 4f 5c [2] 49 69 [2] 67 69 [2] 58 75 }

  condition:
    any of them
}