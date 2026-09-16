rule TTP_XOR_WriteProcessMemory_5b34 {
  strings:
    $key_5b34 = { 0c 46 [2] 3e 64 [2] 38 51 [2] 16 51 [2] 29 4d }

  condition:
    any of them
}