rule TTP_XOR_WriteProcessMemory_3d77 {
  strings:
    $key_3d77 = { 6a 05 [2] 58 27 [2] 5e 12 [2] 70 12 [2] 4f 0e }

  condition:
    any of them
}