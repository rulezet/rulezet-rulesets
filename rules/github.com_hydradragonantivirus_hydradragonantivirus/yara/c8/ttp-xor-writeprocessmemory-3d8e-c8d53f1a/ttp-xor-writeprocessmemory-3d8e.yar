rule TTP_XOR_WriteProcessMemory_3d8e {
  strings:
    $key_3d8e = { 6a fc [2] 58 de [2] 5e eb [2] 70 eb [2] 4f f7 }

  condition:
    any of them
}