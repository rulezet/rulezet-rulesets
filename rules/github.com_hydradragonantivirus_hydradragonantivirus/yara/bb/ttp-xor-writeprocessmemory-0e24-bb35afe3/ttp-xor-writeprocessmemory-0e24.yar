rule TTP_XOR_WriteProcessMemory_0e24 {
  strings:
    $key_0e24 = { 59 56 [2] 6b 74 [2] 6d 41 [2] 43 41 [2] 7c 5d }

  condition:
    any of them
}