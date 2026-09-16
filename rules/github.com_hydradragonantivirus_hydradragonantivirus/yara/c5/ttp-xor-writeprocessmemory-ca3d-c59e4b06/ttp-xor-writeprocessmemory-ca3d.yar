rule TTP_XOR_WriteProcessMemory_ca3d {
  strings:
    $key_ca3d = { 9d 4f [2] af 6d [2] a9 58 [2] 87 58 [2] b8 44 }

  condition:
    any of them
}