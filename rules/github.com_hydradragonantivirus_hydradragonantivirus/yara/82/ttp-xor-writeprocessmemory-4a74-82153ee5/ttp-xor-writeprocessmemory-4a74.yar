rule TTP_XOR_WriteProcessMemory_4a74 {
  strings:
    $key_4a74 = { 1d 06 [2] 2f 24 [2] 29 11 [2] 07 11 [2] 38 0d }

  condition:
    any of them
}