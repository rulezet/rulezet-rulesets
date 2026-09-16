rule TTP_XOR_WriteProcessMemory_0024 {
  strings:
    $key_0024 = { 57 56 [2] 65 74 [2] 63 41 [2] 4d 41 [2] 72 5d }

  condition:
    any of them
}