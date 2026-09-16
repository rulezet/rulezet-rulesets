rule TTP_XOR_WriteProcessMemory_0217 {
  strings:
    $key_0217 = { 55 65 [2] 67 47 [2] 61 72 [2] 4f 72 [2] 70 6e }

  condition:
    any of them
}