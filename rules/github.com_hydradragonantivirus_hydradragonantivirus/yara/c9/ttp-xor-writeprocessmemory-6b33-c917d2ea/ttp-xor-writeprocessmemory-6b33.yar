rule TTP_XOR_WriteProcessMemory_6b33 {
  strings:
    $key_6b33 = { 3c 41 [2] 0e 63 [2] 08 56 [2] 26 56 [2] 19 4a }

  condition:
    any of them
}