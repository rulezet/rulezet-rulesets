rule TTP_XOR_WriteProcessMemory_038d {
  strings:
    $key_038d = { 54 ff [2] 66 dd [2] 60 e8 [2] 4e e8 [2] 71 f4 }

  condition:
    any of them
}