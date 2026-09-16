rule TTP_XOR_WriteProcessMemory_3d23 {
  strings:
    $key_3d23 = { 6a 51 [2] 58 73 [2] 5e 46 [2] 70 46 [2] 4f 5a }

  condition:
    any of them
}