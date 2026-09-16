rule TTP_XOR_WriteProcessMemory_0a60 {
  strings:
    $key_0a60 = { 5d 12 [2] 6f 30 [2] 69 05 [2] 47 05 [2] 78 19 }

  condition:
    any of them
}