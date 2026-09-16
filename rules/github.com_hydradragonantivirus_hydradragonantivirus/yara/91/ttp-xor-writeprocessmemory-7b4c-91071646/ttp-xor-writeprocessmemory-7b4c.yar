rule TTP_XOR_WriteProcessMemory_7b4c {
  strings:
    $key_7b4c = { 2c 3e [2] 1e 1c [2] 18 29 [2] 36 29 [2] 09 35 }

  condition:
    any of them
}