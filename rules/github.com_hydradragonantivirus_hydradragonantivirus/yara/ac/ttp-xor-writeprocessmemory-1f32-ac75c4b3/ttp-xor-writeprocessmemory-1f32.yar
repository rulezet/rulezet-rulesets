rule TTP_XOR_WriteProcessMemory_1f32 {
  strings:
    $key_1f32 = { 48 40 [2] 7a 62 [2] 7c 57 [2] 52 57 [2] 6d 4b }

  condition:
    any of them
}