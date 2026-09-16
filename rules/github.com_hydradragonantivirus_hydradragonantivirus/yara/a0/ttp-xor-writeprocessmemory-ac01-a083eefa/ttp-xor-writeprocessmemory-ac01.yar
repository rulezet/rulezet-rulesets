rule TTP_XOR_WriteProcessMemory_ac01 {
  strings:
    $key_ac01 = { fb 73 [2] c9 51 [2] cf 64 [2] e1 64 [2] de 78 }

  condition:
    any of them
}