rule TTP_XOR_WriteProcessMemory_b46d {
  strings:
    $key_b46d = { e3 1f [2] d1 3d [2] d7 08 [2] f9 08 [2] c6 14 }

  condition:
    any of them
}