rule TTP_XOR_WriteProcessMemory_e3d2 {
  strings:
    $key_e3d2 = { b4 a0 [2] 86 82 [2] 80 b7 [2] ae b7 [2] 91 ab }

  condition:
    any of them
}