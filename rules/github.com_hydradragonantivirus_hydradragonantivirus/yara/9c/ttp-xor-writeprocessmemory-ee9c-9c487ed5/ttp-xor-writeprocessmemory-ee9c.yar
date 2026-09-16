rule TTP_XOR_WriteProcessMemory_ee9c {
  strings:
    $key_ee9c = { b9 ee [2] 8b cc [2] 8d f9 [2] a3 f9 [2] 9c e5 }

  condition:
    any of them
}