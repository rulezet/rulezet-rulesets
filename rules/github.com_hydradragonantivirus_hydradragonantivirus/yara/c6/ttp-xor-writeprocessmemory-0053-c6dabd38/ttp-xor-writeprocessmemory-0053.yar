rule TTP_XOR_WriteProcessMemory_0053 {
  strings:
    $key_0053 = { 57 21 [2] 65 03 [2] 63 36 [2] 4d 36 [2] 72 2a }

  condition:
    any of them
}