rule TTP_XOR_WriteProcessMemory_558d {
  strings:
    $key_558d = { 02 ff [2] 30 dd [2] 36 e8 [2] 18 e8 [2] 27 f4 }

  condition:
    any of them
}