rule TTP_XOR_WriteProcessMemory_f28d {
  strings:
    $key_f28d = { a5 ff [2] 97 dd [2] 91 e8 [2] bf e8 [2] 80 f4 }

  condition:
    any of them
}