rule TTP_XOR_WriteProcessMemory_109a {
  strings:
    $key_109a = { 47 e8 [2] 75 ca [2] 73 ff [2] 5d ff [2] 62 e3 }

  condition:
    any of them
}