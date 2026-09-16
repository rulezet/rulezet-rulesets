rule TTP_XOR_WriteProcessMemory_bf44 {
  strings:
    $key_bf44 = { e8 36 [2] da 14 [2] dc 21 [2] f2 21 [2] cd 3d }

  condition:
    any of them
}