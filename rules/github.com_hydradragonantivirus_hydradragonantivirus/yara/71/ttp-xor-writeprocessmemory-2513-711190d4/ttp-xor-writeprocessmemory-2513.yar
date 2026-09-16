rule TTP_XOR_WriteProcessMemory_2513 {
  strings:
    $key_2513 = { 72 61 [2] 40 43 [2] 46 76 [2] 68 76 [2] 57 6a }

  condition:
    any of them
}