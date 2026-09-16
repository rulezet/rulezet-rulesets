rule TTP_XOR_WriteProcessMemory_5247 {
  strings:
    $key_5247 = { 05 35 [2] 37 17 [2] 31 22 [2] 1f 22 [2] 20 3e }

  condition:
    any of them
}