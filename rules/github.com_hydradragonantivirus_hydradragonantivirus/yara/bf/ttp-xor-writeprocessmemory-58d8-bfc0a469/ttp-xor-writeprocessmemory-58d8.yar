rule TTP_XOR_WriteProcessMemory_58d8 {
  strings:
    $key_58d8 = { 0f aa [2] 3d 88 [2] 3b bd [2] 15 bd [2] 2a a1 }

  condition:
    any of them
}