rule TTP_XOR_WriteProcessMemory_3dab {
  strings:
    $key_3dab = { 6a d9 [2] 58 fb [2] 5e ce [2] 70 ce [2] 4f d2 }

  condition:
    any of them
}