rule TTP_XOR_WriteProcessMemory_4f35 {
  strings:
    $key_4f35 = { 18 47 [2] 2a 65 [2] 2c 50 [2] 02 50 [2] 3d 4c }

  condition:
    any of them
}