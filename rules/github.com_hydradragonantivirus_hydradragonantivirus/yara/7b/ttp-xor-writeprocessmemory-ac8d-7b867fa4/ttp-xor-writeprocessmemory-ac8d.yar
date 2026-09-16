rule TTP_XOR_WriteProcessMemory_ac8d {
  strings:
    $key_ac8d = { fb ff [2] c9 dd [2] cf e8 [2] e1 e8 [2] de f4 }

  condition:
    any of them
}