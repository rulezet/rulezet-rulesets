rule TTP_XOR_WriteProcessMemory_221c {
  strings:
    $key_221c = { 75 6e [2] 47 4c [2] 41 79 [2] 6f 79 [2] 50 65 }

  condition:
    any of them
}