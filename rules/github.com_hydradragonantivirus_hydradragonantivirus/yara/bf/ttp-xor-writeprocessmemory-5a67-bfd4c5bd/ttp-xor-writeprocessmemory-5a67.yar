rule TTP_XOR_WriteProcessMemory_5a67 {
  strings:
    $key_5a67 = { 0d 15 [2] 3f 37 [2] 39 02 [2] 17 02 [2] 28 1e }

  condition:
    any of them
}