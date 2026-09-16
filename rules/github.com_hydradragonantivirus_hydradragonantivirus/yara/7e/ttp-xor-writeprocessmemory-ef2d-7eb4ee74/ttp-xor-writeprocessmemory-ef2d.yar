rule TTP_XOR_WriteProcessMemory_ef2d {
  strings:
    $key_ef2d = { b8 5f [2] 8a 7d [2] 8c 48 [2] a2 48 [2] 9d 54 }

  condition:
    any of them
}