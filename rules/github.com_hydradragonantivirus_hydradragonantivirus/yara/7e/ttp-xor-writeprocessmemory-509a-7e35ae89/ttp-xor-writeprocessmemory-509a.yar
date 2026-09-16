rule TTP_XOR_WriteProcessMemory_509a {
  strings:
    $key_509a = { 07 e8 [2] 35 ca [2] 33 ff [2] 1d ff [2] 22 e3 }

  condition:
    any of them
}