rule TTP_XOR_WriteProcessMemory_1f24 {
  strings:
    $key_1f24 = { 48 56 [2] 7a 74 [2] 7c 41 [2] 52 41 [2] 6d 5d }

  condition:
    any of them
}