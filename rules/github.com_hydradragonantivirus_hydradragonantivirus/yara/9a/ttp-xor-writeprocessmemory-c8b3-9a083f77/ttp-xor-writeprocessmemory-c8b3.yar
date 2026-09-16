rule TTP_XOR_WriteProcessMemory_c8b3 {
  strings:
    $key_c8b3 = { 9f c1 [2] ad e3 [2] ab d6 [2] 85 d6 [2] ba ca }

  condition:
    any of them
}