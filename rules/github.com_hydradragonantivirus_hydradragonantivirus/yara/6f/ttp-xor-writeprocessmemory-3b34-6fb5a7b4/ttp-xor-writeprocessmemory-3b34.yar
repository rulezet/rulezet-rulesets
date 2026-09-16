rule TTP_XOR_WriteProcessMemory_3b34 {
  strings:
    $key_3b34 = { 6c 46 [2] 5e 64 [2] 58 51 [2] 76 51 [2] 49 4d }

  condition:
    any of them
}