rule TTP_XOR_WriteProcessMemory_58e3 {
  strings:
    $key_58e3 = { 0f 91 [2] 3d b3 [2] 3b 86 [2] 15 86 [2] 2a 9a }

  condition:
    any of them
}