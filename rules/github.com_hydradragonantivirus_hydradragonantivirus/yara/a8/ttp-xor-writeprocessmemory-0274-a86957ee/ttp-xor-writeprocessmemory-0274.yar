rule TTP_XOR_WriteProcessMemory_0274 {
  strings:
    $key_0274 = { 55 06 [2] 67 24 [2] 61 11 [2] 4f 11 [2] 70 0d }

  condition:
    any of them
}