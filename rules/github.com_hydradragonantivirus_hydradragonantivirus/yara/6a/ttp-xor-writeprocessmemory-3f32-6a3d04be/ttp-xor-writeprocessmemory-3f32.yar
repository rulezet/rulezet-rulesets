rule TTP_XOR_WriteProcessMemory_3f32 {
  strings:
    $key_3f32 = { 68 40 [2] 5a 62 [2] 5c 57 [2] 72 57 [2] 4d 4b }

  condition:
    any of them
}