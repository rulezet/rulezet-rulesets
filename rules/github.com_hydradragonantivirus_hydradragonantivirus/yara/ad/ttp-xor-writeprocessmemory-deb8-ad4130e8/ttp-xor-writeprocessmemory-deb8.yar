rule TTP_XOR_WriteProcessMemory_deb8 {
  strings:
    $key_deb8 = { 89 ca [2] bb e8 [2] bd dd [2] 93 dd [2] ac c1 }

  condition:
    any of them
}