rule TTP_XOR_WriteProcessMemory_4117 {
  strings:
    $key_4117 = { 16 65 [2] 24 47 [2] 22 72 [2] 0c 72 [2] 33 6e }

  condition:
    any of them
}