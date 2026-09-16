rule TTP_XOR_WriteProcessMemory_f344 {
  strings:
    $key_f344 = { a4 36 [2] 96 14 [2] 90 21 [2] be 21 [2] 81 3d }

  condition:
    any of them
}