rule TTP_XOR_WriteProcessMemory_7847 {
  strings:
    $key_7847 = { 2f 35 [2] 1d 17 [2] 1b 22 [2] 35 22 [2] 0a 3e }

  condition:
    any of them
}