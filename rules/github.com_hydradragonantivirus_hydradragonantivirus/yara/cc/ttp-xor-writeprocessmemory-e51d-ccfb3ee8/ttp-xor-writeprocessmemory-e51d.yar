rule TTP_XOR_WriteProcessMemory_e51d {
  strings:
    $key_e51d = { b2 6f [2] 80 4d [2] 86 78 [2] a8 78 [2] 97 64 }

  condition:
    any of them
}