rule TTP_XOR_WriteProcessMemory_0d1c {
  strings:
    $key_0d1c = { 5a 6e [2] 68 4c [2] 6e 79 [2] 40 79 [2] 7f 65 }

  condition:
    any of them
}