rule TTP_XOR_WriteProcessMemory_3ddf {
  strings:
    $key_3ddf = { 6a ad [2] 58 8f [2] 5e ba [2] 70 ba [2] 4f a6 }

  condition:
    any of them
}