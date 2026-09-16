rule TTP_XOR_WriteProcessMemory_0a33 {
  strings:
    $key_0a33 = { 5d 41 [2] 6f 63 [2] 69 56 [2] 47 56 [2] 78 4a }

  condition:
    any of them
}