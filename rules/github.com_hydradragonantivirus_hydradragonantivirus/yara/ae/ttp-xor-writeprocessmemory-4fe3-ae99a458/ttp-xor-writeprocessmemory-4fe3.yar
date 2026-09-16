rule TTP_XOR_WriteProcessMemory_4fe3 {
  strings:
    $key_4fe3 = { 18 91 [2] 2a b3 [2] 2c 86 [2] 02 86 [2] 3d 9a }

  condition:
    any of them
}