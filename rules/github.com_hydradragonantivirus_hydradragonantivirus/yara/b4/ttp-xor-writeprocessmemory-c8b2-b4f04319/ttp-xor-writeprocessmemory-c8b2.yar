rule TTP_XOR_WriteProcessMemory_c8b2 {
  strings:
    $key_c8b2 = { 9f c0 [2] ad e2 [2] ab d7 [2] 85 d7 [2] ba cb }

  condition:
    any of them
}