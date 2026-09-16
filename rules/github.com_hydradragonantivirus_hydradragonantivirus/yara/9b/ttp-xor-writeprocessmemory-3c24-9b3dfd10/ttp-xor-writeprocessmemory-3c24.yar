rule TTP_XOR_WriteProcessMemory_3c24 {
  strings:
    $key_3c24 = { 6b 56 [2] 59 74 [2] 5f 41 [2] 71 41 [2] 4e 5d }

  condition:
    any of them
}