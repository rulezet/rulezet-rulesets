rule TTP_XOR_WriteProcessMemory_0253 {
  strings:
    $key_0253 = { 55 21 [2] 67 03 [2] 61 36 [2] 4f 36 [2] 70 2a }

  condition:
    any of them
}