rule TTP_XOR_WriteProcessMemory_1752 {
  strings:
    $key_1752 = { 40 20 [2] 72 02 [2] 74 37 [2] 5a 37 [2] 65 2b }

  condition:
    any of them
}