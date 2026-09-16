rule TTP_XOR_WriteProcessMemory_5a24 {
  strings:
    $key_5a24 = { 0d 56 [2] 3f 74 [2] 39 41 [2] 17 41 [2] 28 5d }

  condition:
    any of them
}