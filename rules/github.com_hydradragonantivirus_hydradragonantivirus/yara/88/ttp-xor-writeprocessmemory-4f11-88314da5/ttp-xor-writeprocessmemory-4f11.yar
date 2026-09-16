rule TTP_XOR_WriteProcessMemory_4f11 {
  strings:
    $key_4f11 = { 18 63 [2] 2a 41 [2] 2c 74 [2] 02 74 [2] 3d 68 }

  condition:
    any of them
}