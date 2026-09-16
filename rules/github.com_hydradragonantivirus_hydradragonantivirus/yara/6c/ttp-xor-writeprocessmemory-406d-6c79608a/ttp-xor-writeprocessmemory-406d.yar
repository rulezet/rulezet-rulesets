rule TTP_XOR_WriteProcessMemory_406d {
  strings:
    $key_406d = { 17 1f [2] 25 3d [2] 23 08 [2] 0d 08 [2] 32 14 }

  condition:
    any of them
}