rule TTP_XOR_WriteProcessMemory_6d24 {
  strings:
    $key_6d24 = { 3a 56 [2] 08 74 [2] 0e 41 [2] 20 41 [2] 1f 5d }

  condition:
    any of them
}