rule TTP_XOR_WriteProcessMemory_6a9a {
  strings:
    $key_6a9a = { 3d e8 [2] 0f ca [2] 09 ff [2] 27 ff [2] 18 e3 }

  condition:
    any of them
}