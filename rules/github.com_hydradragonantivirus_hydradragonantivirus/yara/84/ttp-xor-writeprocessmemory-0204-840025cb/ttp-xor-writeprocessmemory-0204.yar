rule TTP_XOR_WriteProcessMemory_0204 {
  strings:
    $key_0204 = { 55 76 [2] 67 54 [2] 61 61 [2] 4f 61 [2] 70 7d }

  condition:
    any of them
}