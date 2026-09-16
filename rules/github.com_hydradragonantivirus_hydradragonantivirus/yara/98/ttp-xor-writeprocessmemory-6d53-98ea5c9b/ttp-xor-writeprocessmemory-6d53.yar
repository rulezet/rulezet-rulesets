rule TTP_XOR_WriteProcessMemory_6d53 {
  strings:
    $key_6d53 = { 3a 21 [2] 08 03 [2] 0e 36 [2] 20 36 [2] 1f 2a }

  condition:
    any of them
}