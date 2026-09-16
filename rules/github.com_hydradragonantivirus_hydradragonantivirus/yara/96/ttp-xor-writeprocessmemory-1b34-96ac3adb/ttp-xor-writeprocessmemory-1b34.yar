rule TTP_XOR_WriteProcessMemory_1b34 {
  strings:
    $key_1b34 = { 4c 46 [2] 7e 64 [2] 78 51 [2] 56 51 [2] 69 4d }

  condition:
    any of them
}