rule TTP_XOR_WriteProcessMemory_0724 {
  strings:
    $key_0724 = { 50 56 [2] 62 74 [2] 64 41 [2] 4a 41 [2] 75 5d }

  condition:
    any of them
}