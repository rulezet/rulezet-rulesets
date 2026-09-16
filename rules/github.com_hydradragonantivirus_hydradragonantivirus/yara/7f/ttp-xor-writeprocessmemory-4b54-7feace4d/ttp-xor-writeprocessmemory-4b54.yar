rule TTP_XOR_WriteProcessMemory_4b54 {
  strings:
    $key_4b54 = { 1c 26 [2] 2e 04 [2] 28 31 [2] 06 31 [2] 39 2d }

  condition:
    any of them
}