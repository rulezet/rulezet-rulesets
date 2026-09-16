rule TTP_XOR_WriteProcessMemory_ff8d {
  strings:
    $key_ff8d = { a8 ff [2] 9a dd [2] 9c e8 [2] b2 e8 [2] 8d f4 }

  condition:
    any of them
}