rule TTP_XOR_WriteProcessMemory_6b54 {
  strings:
    $key_6b54 = { 3c 26 [2] 0e 04 [2] 08 31 [2] 26 31 [2] 19 2d }

  condition:
    any of them
}