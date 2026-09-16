rule TTP_XOR_WriteProcessMemory_888d {
  strings:
    $key_888d = { df ff [2] ed dd [2] eb e8 [2] c5 e8 [2] fa f4 }

  condition:
    any of them
}