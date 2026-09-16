rule TTP_XOR_WriteProcessMemory_6ee4 {
  strings:
    $key_6ee4 = { 39 96 [2] 0b b4 [2] 0d 81 [2] 23 81 [2] 1c 9d }

  condition:
    any of them
}