rule TTP_XOR_WriteProcessMemory_6c47 {
  strings:
    $key_6c47 = { 3b 35 [2] 09 17 [2] 0f 22 [2] 21 22 [2] 1e 3e }

  condition:
    any of them
}