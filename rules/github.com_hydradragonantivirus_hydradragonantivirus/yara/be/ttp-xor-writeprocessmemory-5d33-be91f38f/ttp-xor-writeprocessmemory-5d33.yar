rule TTP_XOR_WriteProcessMemory_5d33 {
  strings:
    $key_5d33 = { 0a 41 [2] 38 63 [2] 3e 56 [2] 10 56 [2] 2f 4a }

  condition:
    any of them
}