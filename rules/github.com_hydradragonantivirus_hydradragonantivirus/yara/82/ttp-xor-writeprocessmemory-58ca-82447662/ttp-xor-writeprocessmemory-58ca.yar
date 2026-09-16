rule TTP_XOR_WriteProcessMemory_58ca {
  strings:
    $key_58ca = { 0f b8 [2] 3d 9a [2] 3b af [2] 15 af [2] 2a b3 }

  condition:
    any of them
}