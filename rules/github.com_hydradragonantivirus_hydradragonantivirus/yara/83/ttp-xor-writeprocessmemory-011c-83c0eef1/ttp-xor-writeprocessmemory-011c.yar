rule TTP_XOR_WriteProcessMemory_011c {
  strings:
    $key_011c = { 56 6e [2] 64 4c [2] 62 79 [2] 4c 79 [2] 73 65 }

  condition:
    any of them
}