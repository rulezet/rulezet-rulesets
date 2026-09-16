rule TTP_XOR_WriteProcessMemory_6e31 {
  strings:
    $key_6e31 = { 39 43 [2] 0b 61 [2] 0d 54 [2] 23 54 [2] 1c 48 }

  condition:
    any of them
}