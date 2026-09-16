rule TTP_XOR_WriteProcessMemory_0643 {
  strings:
    $key_0643 = { 51 31 [2] 63 13 [2] 65 26 [2] 4b 26 [2] 74 3a }

  condition:
    any of them
}