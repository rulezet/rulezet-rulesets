rule TTP_XOR_WriteProcessMemory_6a74 {
  strings:
    $key_6a74 = { 3d 06 [2] 0f 24 [2] 09 11 [2] 27 11 [2] 18 0d }

  condition:
    any of them
}