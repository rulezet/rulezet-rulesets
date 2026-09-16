rule TTP_XOR_WriteProcessMemory_2ff1 {
  strings:
    $key_2ff1 = { 78 83 [2] 4a a1 [2] 4c 94 [2] 62 94 [2] 5d 88 }

  condition:
    any of them
}