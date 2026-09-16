rule TTP_XOR_WriteProcessMemory_1f1c {
  strings:
    $key_1f1c = { 48 6e [2] 7a 4c [2] 7c 79 [2] 52 79 [2] 6d 65 }

  condition:
    any of them
}