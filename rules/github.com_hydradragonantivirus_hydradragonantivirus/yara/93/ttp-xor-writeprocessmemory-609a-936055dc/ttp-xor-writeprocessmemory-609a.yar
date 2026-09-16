rule TTP_XOR_WriteProcessMemory_609a {
  strings:
    $key_609a = { 37 e8 [2] 05 ca [2] 03 ff [2] 2d ff [2] 12 e3 }

  condition:
    any of them
}