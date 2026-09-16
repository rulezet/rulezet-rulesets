rule TTP_XOR_WriteProcessMemory_3ddb {
  strings:
    $key_3ddb = { 6a a9 [2] 58 8b [2] 5e be [2] 70 be [2] 4f a2 }

  condition:
    any of them
}