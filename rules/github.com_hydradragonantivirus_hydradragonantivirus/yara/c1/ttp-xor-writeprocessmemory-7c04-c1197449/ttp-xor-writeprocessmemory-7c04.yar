rule TTP_XOR_WriteProcessMemory_7c04 {
  strings:
    $key_7c04 = { 2b 76 [2] 19 54 [2] 1f 61 [2] 31 61 [2] 0e 7d }

  condition:
    any of them
}