rule TTP_XOR_WriteProcessMemory_bf3d {
  strings:
    $key_bf3d = { e8 4f [2] da 6d [2] dc 58 [2] f2 58 [2] cd 44 }

  condition:
    any of them
}