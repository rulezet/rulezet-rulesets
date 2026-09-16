rule TTP_XOR_WriteProcessMemory_c81c {
  strings:
    $key_c81c = { 9f 6e [2] ad 4c [2] ab 79 [2] 85 79 [2] ba 65 }

  condition:
    any of them
}