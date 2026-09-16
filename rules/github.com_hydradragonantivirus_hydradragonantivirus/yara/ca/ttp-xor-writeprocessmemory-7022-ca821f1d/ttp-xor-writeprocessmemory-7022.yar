rule TTP_XOR_WriteProcessMemory_7022 {
  strings:
    $key_7022 = { 27 50 [2] 15 72 [2] 13 47 [2] 3d 47 [2] 02 5b }

  condition:
    any of them
}