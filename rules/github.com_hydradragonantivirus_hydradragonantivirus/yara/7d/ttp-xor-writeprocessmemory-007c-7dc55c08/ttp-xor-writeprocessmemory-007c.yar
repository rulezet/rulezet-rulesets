rule TTP_XOR_WriteProcessMemory_007c {
  strings:
    $key_007c = { 57 0e [2] 65 2c [2] 63 19 [2] 4d 19 [2] 72 05 }

  condition:
    any of them
}