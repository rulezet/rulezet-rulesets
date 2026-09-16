rule TTP_XOR_WriteProcessMemory_3334 {
  strings:
    $key_3334 = { 64 46 [2] 56 64 [2] 50 51 [2] 7e 51 [2] 41 4d }

  condition:
    any of them
}