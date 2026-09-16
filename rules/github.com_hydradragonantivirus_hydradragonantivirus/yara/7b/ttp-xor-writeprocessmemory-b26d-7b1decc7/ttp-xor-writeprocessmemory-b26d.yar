rule TTP_XOR_WriteProcessMemory_b26d {
  strings:
    $key_b26d = { e5 1f [2] d7 3d [2] d1 08 [2] ff 08 [2] c0 14 }

  condition:
    any of them
}