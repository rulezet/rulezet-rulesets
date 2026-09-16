rule TTP_XOR_WriteProcessMemory_0653 {
  strings:
    $key_0653 = { 51 21 [2] 63 03 [2] 65 36 [2] 4b 36 [2] 74 2a }

  condition:
    any of them
}