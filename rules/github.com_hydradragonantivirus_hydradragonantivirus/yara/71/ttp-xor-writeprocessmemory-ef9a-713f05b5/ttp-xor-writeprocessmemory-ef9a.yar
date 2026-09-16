rule TTP_XOR_WriteProcessMemory_ef9a {
  strings:
    $key_ef9a = { b8 e8 [2] 8a ca [2] 8c ff [2] a2 ff [2] 9d e3 }

  condition:
    any of them
}