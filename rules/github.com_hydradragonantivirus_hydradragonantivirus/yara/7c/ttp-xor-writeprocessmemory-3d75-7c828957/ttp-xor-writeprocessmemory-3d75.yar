rule TTP_XOR_WriteProcessMemory_3d75 {
  strings:
    $key_3d75 = { 6a 07 [2] 58 25 [2] 5e 10 [2] 70 10 [2] 4f 0c }

  condition:
    any of them
}