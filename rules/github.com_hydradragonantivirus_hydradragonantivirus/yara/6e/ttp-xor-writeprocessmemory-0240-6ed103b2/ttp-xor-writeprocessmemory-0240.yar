rule TTP_XOR_WriteProcessMemory_0240 {
  strings:
    $key_0240 = { 55 32 [2] 67 10 [2] 61 25 [2] 4f 25 [2] 70 39 }

  condition:
    any of them
}