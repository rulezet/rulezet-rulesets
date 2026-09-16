rule TTP_XOR_WriteProcessMemory_2a74 {
  strings:
    $key_2a74 = { 7d 06 [2] 4f 24 [2] 49 11 [2] 67 11 [2] 58 0d }

  condition:
    any of them
}