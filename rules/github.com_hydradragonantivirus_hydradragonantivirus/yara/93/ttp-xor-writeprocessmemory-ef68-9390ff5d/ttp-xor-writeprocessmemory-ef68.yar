rule TTP_XOR_WriteProcessMemory_ef68 {
  strings:
    $key_ef68 = { b8 1a [2] 8a 38 [2] 8c 0d [2] a2 0d [2] 9d 11 }

  condition:
    any of them
}