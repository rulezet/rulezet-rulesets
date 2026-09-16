rule TTP_XOR_WriteProcessMemory_178d {
  strings:
    $key_178d = { 40 ff [2] 72 dd [2] 74 e8 [2] 5a e8 [2] 65 f4 }

  condition:
    any of them
}