rule TTP_XOR_WriteProcessMemory_0c53 {
  strings:
    $key_0c53 = { 5b 21 [2] 69 03 [2] 6f 36 [2] 41 36 [2] 7e 2a }

  condition:
    any of them
}