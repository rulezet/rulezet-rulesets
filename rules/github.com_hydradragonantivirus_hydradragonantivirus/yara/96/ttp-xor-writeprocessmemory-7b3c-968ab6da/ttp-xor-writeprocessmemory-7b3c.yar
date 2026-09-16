rule TTP_XOR_WriteProcessMemory_7b3c {
  strings:
    $key_7b3c = { 2c 4e [2] 1e 6c [2] 18 59 [2] 36 59 [2] 09 45 }

  condition:
    any of them
}