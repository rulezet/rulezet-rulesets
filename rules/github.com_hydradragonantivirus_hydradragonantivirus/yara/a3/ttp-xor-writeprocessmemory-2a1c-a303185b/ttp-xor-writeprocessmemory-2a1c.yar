rule TTP_XOR_WriteProcessMemory_2a1c {
  strings:
    $key_2a1c = { 7d 6e [2] 4f 4c [2] 49 79 [2] 67 79 [2] 58 65 }

  condition:
    any of them
}