rule TTP_XOR_WriteProcessMemory_0732 {
  strings:
    $key_0732 = { 50 40 [2] 62 62 [2] 64 57 [2] 4a 57 [2] 75 4b }

  condition:
    any of them
}