rule TTP_XOR_WriteProcessMemory_0a30 {
  strings:
    $key_0a30 = { 5d 42 [2] 6f 60 [2] 69 55 [2] 47 55 [2] 78 49 }

  condition:
    any of them
}