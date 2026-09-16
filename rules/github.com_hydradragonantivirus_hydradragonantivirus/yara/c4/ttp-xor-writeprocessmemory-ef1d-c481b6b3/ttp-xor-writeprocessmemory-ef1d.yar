rule TTP_XOR_WriteProcessMemory_ef1d {
  strings:
    $key_ef1d = { b8 6f [2] 8a 4d [2] 8c 78 [2] a2 78 [2] 9d 64 }

  condition:
    any of them
}