rule TTP_XOR_WriteProcessMemory_258d {
  strings:
    $key_258d = { 72 ff [2] 40 dd [2] 46 e8 [2] 68 e8 [2] 57 f4 }

  condition:
    any of them
}