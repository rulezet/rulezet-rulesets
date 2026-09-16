rule TTP_XOR_WriteProcessMemory_667c {
  strings:
    $key_667c = { 31 0e [2] 03 2c [2] 05 19 [2] 2b 19 [2] 14 05 }

  condition:
    any of them
}