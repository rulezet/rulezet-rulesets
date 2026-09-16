rule TTP_XOR_WriteProcessMemory_041c {
  strings:
    $key_041c = { 53 6e [2] 61 4c [2] 67 79 [2] 49 79 [2] 76 65 }

  condition:
    any of them
}