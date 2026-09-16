rule TTP_XOR_WriteProcessMemory_3f14 {
  strings:
    $key_3f14 = { 68 66 [2] 5a 44 [2] 5c 71 [2] 72 71 [2] 4d 6d }

  condition:
    any of them
}