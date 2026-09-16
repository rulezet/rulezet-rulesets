rule TTP_XOR_WriteProcessMemory_3d31 {
  strings:
    $key_3d31 = { 6a 43 [2] 58 61 [2] 5e 54 [2] 70 54 [2] 4f 48 }

  condition:
    any of them
}