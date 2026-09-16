rule TTP_XOR_WriteProcessMemory_1914 {
  strings:
    $key_1914 = { 4e 66 [2] 7c 44 [2] 7a 71 [2] 54 71 [2] 6b 6d }

  condition:
    any of them
}