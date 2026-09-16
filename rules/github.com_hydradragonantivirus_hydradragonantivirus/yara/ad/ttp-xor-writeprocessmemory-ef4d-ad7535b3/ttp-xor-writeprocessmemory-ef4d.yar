rule TTP_XOR_WriteProcessMemory_ef4d {
  strings:
    $key_ef4d = { b8 3f [2] 8a 1d [2] 8c 28 [2] a2 28 [2] 9d 34 }

  condition:
    any of them
}