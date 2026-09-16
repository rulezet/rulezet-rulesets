rule TTP_XOR_WriteProcessMemory_5a45 {
  strings:
    $key_5a45 = { 0d 37 [2] 3f 15 [2] 39 20 [2] 17 20 [2] 28 3c }

  condition:
    any of them
}