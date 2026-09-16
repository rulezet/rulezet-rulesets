rule TTP_XOR_WriteProcessMemory_4334 {
  strings:
    $key_4334 = { 14 46 [2] 26 64 [2] 20 51 [2] 0e 51 [2] 31 4d }

  condition:
    any of them
}