rule TTP_XOR_WriteProcessMemory_c8b4 {
  strings:
    $key_c8b4 = { 9f c6 [2] ad e4 [2] ab d1 [2] 85 d1 [2] ba cd }

  condition:
    any of them
}