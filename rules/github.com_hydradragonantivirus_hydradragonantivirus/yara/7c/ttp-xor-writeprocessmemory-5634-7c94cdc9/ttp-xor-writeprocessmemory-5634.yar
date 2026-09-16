rule TTP_XOR_WriteProcessMemory_5634 {
  strings:
    $key_5634 = { 01 46 [2] 33 64 [2] 35 51 [2] 1b 51 [2] 24 4d }

  condition:
    any of them
}