rule TTP_XOR_WriteProcessMemory_3d1c {
  strings:
    $key_3d1c = { 6a 6e [2] 58 4c [2] 5e 79 [2] 70 79 [2] 4f 65 }

  condition:
    any of them
}