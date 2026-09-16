rule TTP_XOR_WriteProcessMemory_6e9a {
  strings:
    $key_6e9a = { 39 e8 [2] 0b ca [2] 0d ff [2] 23 ff [2] 1c e3 }

  condition:
    any of them
}