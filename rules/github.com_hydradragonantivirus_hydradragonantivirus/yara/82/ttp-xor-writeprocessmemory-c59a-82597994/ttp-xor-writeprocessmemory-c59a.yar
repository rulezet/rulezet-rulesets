rule TTP_XOR_WriteProcessMemory_c59a {
  strings:
    $key_c59a = { 92 e8 [2] a0 ca [2] a6 ff [2] 88 ff [2] b7 e3 }

  condition:
    any of them
}