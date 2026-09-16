rule TTP_XOR_WriteProcessMemory_e8e8 {
  strings:
    $key_e8e8 = { bf 9a [2] 8d b8 [2] 8b 8d [2] a5 8d [2] 9a 91 }

  condition:
    any of them
}