rule TTP_XOR_WriteProcessMemory_5d34 {
  strings:
    $key_5d34 = { 0a 46 [2] 38 64 [2] 3e 51 [2] 10 51 [2] 2f 4d }

  condition:
    any of them
}