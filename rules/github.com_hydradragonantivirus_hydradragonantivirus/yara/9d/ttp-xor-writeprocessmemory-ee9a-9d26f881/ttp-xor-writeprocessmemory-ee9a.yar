rule TTP_XOR_WriteProcessMemory_ee9a {
  strings:
    $key_ee9a = { b9 e8 [2] 8b ca [2] 8d ff [2] a3 ff [2] 9c e3 }

  condition:
    any of them
}