rule TTP_XOR_WriteProcessMemory_328d {
  strings:
    $key_328d = { 65 ff [2] 57 dd [2] 51 e8 [2] 7f e8 [2] 40 f4 }

  condition:
    any of them
}