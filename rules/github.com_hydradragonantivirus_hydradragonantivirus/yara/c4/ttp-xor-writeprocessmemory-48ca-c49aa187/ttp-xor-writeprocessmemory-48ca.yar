rule TTP_XOR_WriteProcessMemory_48ca {
  strings:
    $key_48ca = { 1f b8 [2] 2d 9a [2] 2b af [2] 05 af [2] 3a b3 }

  condition:
    any of them
}