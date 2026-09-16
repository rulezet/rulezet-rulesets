rule TTP_XOR_WriteProcessMemory_bf6d {
  strings:
    $key_bf6d = { e8 1f [2] da 3d [2] dc 08 [2] f2 08 [2] cd 14 }

  condition:
    any of them
}