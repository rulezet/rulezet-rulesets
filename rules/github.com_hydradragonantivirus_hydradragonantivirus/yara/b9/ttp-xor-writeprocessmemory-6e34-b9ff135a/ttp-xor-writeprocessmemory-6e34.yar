rule TTP_XOR_WriteProcessMemory_6e34 {
  strings:
    $key_6e34 = { 39 46 [2] 0b 64 [2] 0d 51 [2] 23 51 [2] 1c 4d }

  condition:
    any of them
}