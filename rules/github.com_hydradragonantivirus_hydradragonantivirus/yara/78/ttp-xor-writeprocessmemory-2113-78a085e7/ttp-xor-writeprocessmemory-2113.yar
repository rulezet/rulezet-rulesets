rule TTP_XOR_WriteProcessMemory_2113 {
  strings:
    $key_2113 = { 76 61 [2] 44 43 [2] 42 76 [2] 6c 76 [2] 53 6a }

  condition:
    any of them
}