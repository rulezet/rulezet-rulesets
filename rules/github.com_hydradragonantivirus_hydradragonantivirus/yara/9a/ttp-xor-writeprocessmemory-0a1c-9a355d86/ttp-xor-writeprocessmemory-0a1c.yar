rule TTP_XOR_WriteProcessMemory_0a1c {
  strings:
    $key_0a1c = { 5d 6e [2] 6f 4c [2] 69 79 [2] 47 79 [2] 78 65 }

  condition:
    any of them
}