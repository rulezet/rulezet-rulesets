rule TTP_XOR_WriteProcessMemory_7d47 {
  strings:
    $key_7d47 = { 2a 35 [2] 18 17 [2] 1e 22 [2] 30 22 [2] 0f 3e }

  condition:
    any of them
}