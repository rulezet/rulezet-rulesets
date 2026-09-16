rule TTP_XOR_WriteProcessMemory_3d27 {
  strings:
    $key_3d27 = { 6a 55 [2] 58 77 [2] 5e 42 [2] 70 42 [2] 4f 5e }

  condition:
    any of them
}