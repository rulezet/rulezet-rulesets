rule TTP_XOR_WriteProcessMemory_cc3d {
  strings:
    $key_cc3d = { 9b 4f [2] a9 6d [2] af 58 [2] 81 58 [2] be 44 }

  condition:
    any of them
}