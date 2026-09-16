rule TTP_XOR_WriteProcessMemory_0a74 {
  strings:
    $key_0a74 = { 5d 06 [2] 6f 24 [2] 69 11 [2] 47 11 [2] 78 0d }

  condition:
    any of them
}