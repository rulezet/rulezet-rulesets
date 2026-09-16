rule TTP_XOR_WriteProcessMemory_e38d {
  strings:
    $key_e38d = { b4 ff [2] 86 dd [2] 80 e8 [2] ae e8 [2] 91 f4 }

  condition:
    any of them
}