rule TTP_XOR_WriteProcessMemory_0264 {
  strings:
    $key_0264 = { 55 16 [2] 67 34 [2] 61 01 [2] 4f 01 [2] 70 1d }

  condition:
    any of them
}