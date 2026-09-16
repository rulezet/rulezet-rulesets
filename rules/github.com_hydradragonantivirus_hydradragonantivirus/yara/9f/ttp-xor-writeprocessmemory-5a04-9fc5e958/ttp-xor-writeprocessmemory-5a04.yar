rule TTP_XOR_WriteProcessMemory_5a04 {
  strings:
    $key_5a04 = { 0d 76 [2] 3f 54 [2] 39 61 [2] 17 61 [2] 28 7d }

  condition:
    any of them
}