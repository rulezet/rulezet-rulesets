rule TTP_XOR_WriteProcessMemory_0247 {
  strings:
    $key_0247 = { 55 35 [2] 67 17 [2] 61 22 [2] 4f 22 [2] 70 3e }

  condition:
    any of them
}