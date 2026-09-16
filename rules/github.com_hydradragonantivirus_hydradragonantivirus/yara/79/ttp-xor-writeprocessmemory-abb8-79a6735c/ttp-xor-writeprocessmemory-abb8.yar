rule TTP_XOR_WriteProcessMemory_abb8 {
  strings:
    $key_abb8 = { fc ca [2] ce e8 [2] c8 dd [2] e6 dd [2] d9 c1 }

  condition:
    any of them
}