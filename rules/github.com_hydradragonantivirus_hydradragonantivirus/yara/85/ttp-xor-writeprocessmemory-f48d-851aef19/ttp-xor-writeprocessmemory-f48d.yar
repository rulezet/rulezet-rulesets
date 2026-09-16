rule TTP_XOR_WriteProcessMemory_f48d {
  strings:
    $key_f48d = { a3 ff [2] 91 dd [2] 97 e8 [2] b9 e8 [2] 86 f4 }

  condition:
    any of them
}