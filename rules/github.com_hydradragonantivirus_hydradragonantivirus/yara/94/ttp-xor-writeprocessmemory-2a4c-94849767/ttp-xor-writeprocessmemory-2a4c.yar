rule TTP_XOR_WriteProcessMemory_2a4c {
  strings:
    $key_2a4c = { 7d 3e [2] 4f 1c [2] 49 29 [2] 67 29 [2] 58 35 }

  condition:
    any of them
}