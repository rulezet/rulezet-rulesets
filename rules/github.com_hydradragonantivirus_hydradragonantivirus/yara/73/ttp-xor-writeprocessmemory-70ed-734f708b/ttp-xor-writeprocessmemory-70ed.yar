rule TTP_XOR_WriteProcessMemory_70ed {
  strings:
    $key_70ed = { 27 9f [2] 15 bd [2] 13 88 [2] 3d 88 [2] 02 94 }

  condition:
    any of them
}