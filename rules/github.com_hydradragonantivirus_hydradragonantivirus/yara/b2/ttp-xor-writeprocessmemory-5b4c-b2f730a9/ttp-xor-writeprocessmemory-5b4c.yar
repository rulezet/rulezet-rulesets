rule TTP_XOR_WriteProcessMemory_5b4c {
  strings:
    $key_5b4c = { 0c 3e [2] 3e 1c [2] 38 29 [2] 16 29 [2] 29 35 }

  condition:
    any of them
}