rule TTP_XOR_WriteProcessMemory_3274 {
  strings:
    $key_3274 = { 65 06 [2] 57 24 [2] 51 11 [2] 7f 11 [2] 40 0d }

  condition:
    any of them
}