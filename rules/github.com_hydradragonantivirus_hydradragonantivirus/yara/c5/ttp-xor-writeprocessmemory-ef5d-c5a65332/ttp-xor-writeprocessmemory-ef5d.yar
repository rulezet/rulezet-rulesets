rule TTP_XOR_WriteProcessMemory_ef5d {
  strings:
    $key_ef5d = { b8 2f [2] 8a 0d [2] 8c 38 [2] a2 38 [2] 9d 24 }

  condition:
    any of them
}