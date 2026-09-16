rule TTP_XOR_WriteProcessMemory_ee9d {
  strings:
    $key_ee9d = { b9 ef [2] 8b cd [2] 8d f8 [2] a3 f8 [2] 9c e4 }

  condition:
    any of them
}