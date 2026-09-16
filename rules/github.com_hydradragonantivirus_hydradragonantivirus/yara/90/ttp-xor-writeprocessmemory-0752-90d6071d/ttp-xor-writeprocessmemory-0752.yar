rule TTP_XOR_WriteProcessMemory_0752 {
  strings:
    $key_0752 = { 50 20 [2] 62 02 [2] 64 37 [2] 4a 37 [2] 75 2b }

  condition:
    any of them
}