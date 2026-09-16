rule TTP_XOR_WriteProcessMemory_0a45 {
  strings:
    $key_0a45 = { 5d 37 [2] 6f 15 [2] 69 20 [2] 47 20 [2] 78 3c }

  condition:
    any of them
}