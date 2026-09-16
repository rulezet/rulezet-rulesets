rule TTP_XOR_WriteProcessMemory_6904 {
  strings:
    $key_6904 = { 3e 76 [2] 0c 54 [2] 0a 61 [2] 24 61 [2] 1b 7d }

  condition:
    any of them
}