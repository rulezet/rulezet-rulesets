rule TTP_XOR_WriteProcessMemory_3c04 {
  strings:
    $key_3c04 = { 6b 76 [2] 59 54 [2] 5f 61 [2] 71 61 [2] 4e 7d }

  condition:
    any of them
}