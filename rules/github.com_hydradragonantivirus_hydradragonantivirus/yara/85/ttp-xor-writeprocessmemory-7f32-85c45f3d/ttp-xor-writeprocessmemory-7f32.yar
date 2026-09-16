rule TTP_XOR_WriteProcessMemory_7f32 {
  strings:
    $key_7f32 = { 28 40 [2] 1a 62 [2] 1c 57 [2] 32 57 [2] 0d 4b }

  condition:
    any of them
}