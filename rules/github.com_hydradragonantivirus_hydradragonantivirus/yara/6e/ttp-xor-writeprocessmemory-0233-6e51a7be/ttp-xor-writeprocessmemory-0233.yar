rule TTP_XOR_WriteProcessMemory_0233 {
  strings:
    $key_0233 = { 55 41 [2] 67 63 [2] 61 56 [2] 4f 56 [2] 70 4a }

  condition:
    any of them
}