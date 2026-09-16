rule TTP_XOR_WriteProcessMemory_988d {
  strings:
    $key_988d = { cf ff [2] fd dd [2] fb e8 [2] d5 e8 [2] ea f4 }

  condition:
    any of them
}