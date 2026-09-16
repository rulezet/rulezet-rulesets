rule TTP_XOR_WriteProcessMemory_587c {
  strings:
    $key_587c = { 0f 0e [2] 3d 2c [2] 3b 19 [2] 15 19 [2] 2a 05 }

  condition:
    any of them
}