rule TTP_XOR_WriteProcessMemory_0c63 {
  strings:
    $key_0c63 = { 5b 11 [2] 69 33 [2] 6f 06 [2] 41 06 [2] 7e 1a }

  condition:
    any of them
}