rule TTP_XOR_WriteProcessMemory_ca9a {
  strings:
    $key_ca9a = { 9d e8 [2] af ca [2] a9 ff [2] 87 ff [2] b8 e3 }

  condition:
    any of them
}