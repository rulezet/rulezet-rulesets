rule TTP_XOR_WriteProcessMemory_3d0c {
  strings:
    $key_3d0c = { 6a 7e [2] 58 5c [2] 5e 69 [2] 70 69 [2] 4f 75 }

  condition:
    any of them
}