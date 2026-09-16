rule TTP_XOR_WriteProcessMemory_c88d {
  strings:
    $key_c88d = { 9f ff [2] ad dd [2] ab e8 [2] 85 e8 [2] ba f4 }

  condition:
    any of them
}