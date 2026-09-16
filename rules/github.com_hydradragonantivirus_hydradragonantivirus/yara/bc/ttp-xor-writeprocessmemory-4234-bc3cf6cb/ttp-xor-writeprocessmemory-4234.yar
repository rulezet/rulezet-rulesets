rule TTP_XOR_WriteProcessMemory_4234 {
  strings:
    $key_4234 = { 15 46 [2] 27 64 [2] 21 51 [2] 0f 51 [2] 30 4d }

  condition:
    any of them
}