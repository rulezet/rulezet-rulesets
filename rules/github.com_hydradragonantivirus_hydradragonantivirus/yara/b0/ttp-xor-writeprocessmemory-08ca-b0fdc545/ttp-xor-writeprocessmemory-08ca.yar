rule TTP_XOR_WriteProcessMemory_08ca {
  strings:
    $key_08ca = { 5f b8 [2] 6d 9a [2] 6b af [2] 45 af [2] 7a b3 }

  condition:
    any of them
}