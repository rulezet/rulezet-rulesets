rule TTP_XOR_WriteProcessMemory_5b54 {
  strings:
    $key_5b54 = { 0c 26 [2] 3e 04 [2] 38 31 [2] 16 31 [2] 29 2d }

  condition:
    any of them
}