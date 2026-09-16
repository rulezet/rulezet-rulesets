rule TTP_XOR_WriteProcessMemory_5534 {
  strings:
    $key_5534 = { 02 46 [2] 30 64 [2] 36 51 [2] 18 51 [2] 27 4d }

  condition:
    any of them
}