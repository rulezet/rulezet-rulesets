rule TTP_XOR_WriteProcessMemory_7a74 {
  strings:
    $key_7a74 = { 2d 06 [2] 1f 24 [2] 19 11 [2] 37 11 [2] 08 0d }

  condition:
    any of them
}