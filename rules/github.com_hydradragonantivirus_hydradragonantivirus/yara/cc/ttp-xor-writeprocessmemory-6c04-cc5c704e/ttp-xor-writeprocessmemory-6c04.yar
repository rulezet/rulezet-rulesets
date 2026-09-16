rule TTP_XOR_WriteProcessMemory_6c04 {
  strings:
    $key_6c04 = { 3b 76 [2] 09 54 [2] 0f 61 [2] 21 61 [2] 1e 7d }

  condition:
    any of them
}