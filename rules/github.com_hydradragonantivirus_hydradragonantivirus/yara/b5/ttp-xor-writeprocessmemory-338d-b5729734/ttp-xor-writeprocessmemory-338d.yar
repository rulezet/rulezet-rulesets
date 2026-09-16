rule TTP_XOR_WriteProcessMemory_338d {
  strings:
    $key_338d = { 64 ff [2] 56 dd [2] 50 e8 [2] 7e e8 [2] 41 f4 }

  condition:
    any of them
}