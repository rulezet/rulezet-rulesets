rule TTP_XOR_WriteProcessMemory_6e64 {
  strings:
    $key_6e64 = { 39 16 [2] 0b 34 [2] 0d 01 [2] 23 01 [2] 1c 1d }

  condition:
    any of them
}