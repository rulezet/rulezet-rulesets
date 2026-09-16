rule TTP_XOR_WriteProcessMemory_6404 {
  strings:
    $key_6404 = { 33 76 [2] 01 54 [2] 07 61 [2] 29 61 [2] 16 7d }

  condition:
    any of them
}