rule TTP_XOR_WriteProcessMemory_6c64 {
  strings:
    $key_6c64 = { 3b 16 [2] 09 34 [2] 0f 01 [2] 21 01 [2] 1e 1d }

  condition:
    any of them
}