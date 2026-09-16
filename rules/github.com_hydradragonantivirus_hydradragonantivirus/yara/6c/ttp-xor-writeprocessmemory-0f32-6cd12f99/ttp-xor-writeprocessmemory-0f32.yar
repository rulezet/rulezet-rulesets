rule TTP_XOR_WriteProcessMemory_0f32 {
  strings:
    $key_0f32 = { 58 40 [2] 6a 62 [2] 6c 57 [2] 42 57 [2] 7d 4b }

  condition:
    any of them
}