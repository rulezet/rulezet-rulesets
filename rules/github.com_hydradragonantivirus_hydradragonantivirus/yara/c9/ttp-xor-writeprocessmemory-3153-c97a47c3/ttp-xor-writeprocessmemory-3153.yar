rule TTP_XOR_WriteProcessMemory_3153 {
  strings:
    $key_3153 = { 66 21 [2] 54 03 [2] 52 36 [2] 7c 36 [2] 43 2a }

  condition:
    any of them
}