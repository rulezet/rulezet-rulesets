rule TTP_XOR_WriteProcessMemory_097c {
  strings:
    $key_097c = { 5e 0e [2] 6c 2c [2] 6a 19 [2] 44 19 [2] 7b 05 }

  condition:
    any of them
}