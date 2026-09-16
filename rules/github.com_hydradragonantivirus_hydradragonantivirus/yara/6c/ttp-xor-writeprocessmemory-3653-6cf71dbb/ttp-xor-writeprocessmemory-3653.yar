rule TTP_XOR_WriteProcessMemory_3653 {
  strings:
    $key_3653 = { 61 21 [2] 53 03 [2] 55 36 [2] 7b 36 [2] 44 2a }

  condition:
    any of them
}