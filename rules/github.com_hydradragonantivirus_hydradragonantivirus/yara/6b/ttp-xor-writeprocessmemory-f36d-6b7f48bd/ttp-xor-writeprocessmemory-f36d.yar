rule TTP_XOR_WriteProcessMemory_f36d {
  strings:
    $key_f36d = { a4 1f [2] 96 3d [2] 90 08 [2] be 08 [2] 81 14 }

  condition:
    any of them
}