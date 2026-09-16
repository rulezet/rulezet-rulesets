rule TTP_XOR_WriteProcessMemory_4122 {
  strings:
    $key_4122 = { 16 50 [2] 24 72 [2] 22 47 [2] 0c 47 [2] 33 5b }

  condition:
    any of them
}