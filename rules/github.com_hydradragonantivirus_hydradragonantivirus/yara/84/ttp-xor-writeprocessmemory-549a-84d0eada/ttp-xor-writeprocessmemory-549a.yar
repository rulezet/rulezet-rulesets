rule TTP_XOR_WriteProcessMemory_549a {
  strings:
    $key_549a = { 03 e8 [2] 31 ca [2] 37 ff [2] 19 ff [2] 26 e3 }

  condition:
    any of them
}