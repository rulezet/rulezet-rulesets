rule TTP_XOR_WriteProcessMemory_3a74 {
  strings:
    $key_3a74 = { 6d 06 [2] 5f 24 [2] 59 11 [2] 77 11 [2] 48 0d }

  condition:
    any of them
}