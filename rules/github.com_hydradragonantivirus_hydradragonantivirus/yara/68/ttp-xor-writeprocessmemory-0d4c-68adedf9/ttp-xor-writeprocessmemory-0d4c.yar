rule TTP_XOR_WriteProcessMemory_0d4c {
  strings:
    $key_0d4c = { 5a 3e [2] 68 1c [2] 6e 29 [2] 40 29 [2] 7f 35 }

  condition:
    any of them
}