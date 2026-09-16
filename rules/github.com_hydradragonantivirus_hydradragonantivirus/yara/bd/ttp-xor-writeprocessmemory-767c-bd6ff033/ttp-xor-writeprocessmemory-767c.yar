rule TTP_XOR_WriteProcessMemory_767c {
  strings:
    $key_767c = { 21 0e [2] 13 2c [2] 15 19 [2] 3b 19 [2] 04 05 }

  condition:
    any of them
}