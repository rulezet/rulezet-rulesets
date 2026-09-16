rule TTP_XOR_WriteProcessMemory_5a74 {
  strings:
    $key_5a74 = { 0d 06 [2] 3f 24 [2] 39 11 [2] 17 11 [2] 28 0d }

  condition:
    any of them
}