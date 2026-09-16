rule TTP_XOR_WriteProcessMemory_aa6d {
  strings:
    $key_aa6d = { fd 1f [2] cf 3d [2] c9 08 [2] e7 08 [2] d8 14 }

  condition:
    any of them
}