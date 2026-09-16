rule TTP_XOR_WriteProcessMemory_3dcc {
  strings:
    $key_3dcc = { 6a be [2] 58 9c [2] 5e a9 [2] 70 a9 [2] 4f b5 }

  condition:
    any of them
}