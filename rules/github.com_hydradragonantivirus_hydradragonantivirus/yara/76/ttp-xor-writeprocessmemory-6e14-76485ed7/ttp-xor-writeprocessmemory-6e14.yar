rule TTP_XOR_WriteProcessMemory_6e14 {
  strings:
    $key_6e14 = { 39 66 [2] 0b 44 [2] 0d 71 [2] 23 71 [2] 1c 6d }

  condition:
    any of them
}