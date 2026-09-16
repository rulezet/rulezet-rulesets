rule TTP_XOR_WriteProcessMemory_3f24 {
  strings:
    $key_3f24 = { 68 56 [2] 5a 74 [2] 5c 41 [2] 72 41 [2] 4d 5d }

  condition:
    any of them
}