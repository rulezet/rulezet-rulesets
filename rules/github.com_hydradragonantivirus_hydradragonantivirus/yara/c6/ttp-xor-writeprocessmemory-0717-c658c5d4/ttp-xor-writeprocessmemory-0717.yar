rule TTP_XOR_WriteProcessMemory_0717 {
  strings:
    $key_0717 = { 50 65 [2] 62 47 [2] 64 72 [2] 4a 72 [2] 75 6e }

  condition:
    any of them
}