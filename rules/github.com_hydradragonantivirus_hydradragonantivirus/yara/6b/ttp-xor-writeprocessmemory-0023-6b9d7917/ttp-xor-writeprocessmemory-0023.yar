rule TTP_XOR_WriteProcessMemory_0023 {
  strings:
    $key_0023 = { 57 51 [2] 65 73 [2] 63 46 [2] 4d 46 [2] 72 5a }

  condition:
    any of them
}