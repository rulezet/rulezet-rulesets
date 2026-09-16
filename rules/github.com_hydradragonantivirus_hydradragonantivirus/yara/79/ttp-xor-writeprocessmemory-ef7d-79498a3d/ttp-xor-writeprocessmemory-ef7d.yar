rule TTP_XOR_WriteProcessMemory_ef7d {
  strings:
    $key_ef7d = { b8 0f [2] 8a 2d [2] 8c 18 [2] a2 18 [2] 9d 04 }

  condition:
    any of them
}