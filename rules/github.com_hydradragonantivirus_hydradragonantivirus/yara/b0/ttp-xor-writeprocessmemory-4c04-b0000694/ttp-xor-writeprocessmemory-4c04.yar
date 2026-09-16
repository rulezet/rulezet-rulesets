rule TTP_XOR_WriteProcessMemory_4c04 {
  strings:
    $key_4c04 = { 1b 76 [2] 29 54 [2] 2f 61 [2] 01 61 [2] 3e 7d }

  condition:
    any of them
}