rule TTP_XOR_WriteProcessMemory_3524 {
  strings:
    $key_3524 = { 62 56 [2] 50 74 [2] 56 41 [2] 78 41 [2] 47 5d }

  condition:
    any of them
}