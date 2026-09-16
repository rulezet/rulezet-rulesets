rule TTP_XOR_WriteProcessMemory_3e32 {
  strings:
    $key_3e32 = { 69 40 [2] 5b 62 [2] 5d 57 [2] 73 57 [2] 4c 4b }

  condition:
    any of them
}