rule TTP_XOR_WriteProcessMemory_3d69 {
  strings:
    $key_3d69 = { 6a 1b [2] 58 39 [2] 5e 0c [2] 70 0c [2] 4f 10 }

  condition:
    any of them
}