rule TTP_XOR_WriteProcessMemory_3d5c {
  strings:
    $key_3d5c = { 6a 2e [2] 58 0c [2] 5e 39 [2] 70 39 [2] 4f 25 }

  condition:
    any of them
}