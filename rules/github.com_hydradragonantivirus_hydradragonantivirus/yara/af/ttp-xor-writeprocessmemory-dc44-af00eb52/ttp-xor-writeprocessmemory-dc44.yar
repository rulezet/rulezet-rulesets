rule TTP_XOR_WriteProcessMemory_dc44 {
  strings:
    $key_dc44 = { 8b 36 [2] b9 14 [2] bf 21 [2] 91 21 [2] ae 3d }

  condition:
    any of them
}