rule TTP_XOR_WriteProcessMemory_238d {
  strings:
    $key_238d = { 74 ff [2] 46 dd [2] 40 e8 [2] 6e e8 [2] 51 f4 }

  condition:
    any of them
}