rule TTP_XOR_WriteProcessMemory_208d {
  strings:
    $key_208d = { 77 ff [2] 45 dd [2] 43 e8 [2] 6d e8 [2] 52 f4 }

  condition:
    any of them
}