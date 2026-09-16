rule TTP_XOR_WriteProcessMemory_3752 {
  strings:
    $key_3752 = { 60 20 [2] 52 02 [2] 54 37 [2] 7a 37 [2] 45 2b }

  condition:
    any of them
}