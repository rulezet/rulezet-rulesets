rule TTP_XOR_WriteProcessMemory_e652 {
  strings:
    $key_e652 = { b1 20 [2] 83 02 [2] 85 37 [2] ab 37 [2] 94 2b }

  condition:
    any of them
}