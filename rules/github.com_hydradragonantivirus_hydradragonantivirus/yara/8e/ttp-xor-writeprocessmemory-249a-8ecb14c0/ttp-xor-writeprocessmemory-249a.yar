rule TTP_XOR_WriteProcessMemory_249a {
  strings:
    $key_249a = { 73 e8 [2] 41 ca [2] 47 ff [2] 69 ff [2] 56 e3 }

  condition:
    any of them
}