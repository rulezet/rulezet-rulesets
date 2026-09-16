rule TTP_XOR_WriteProcessMemory_3dfe {
  strings:
    $key_3dfe = { 6a 8c [2] 58 ae [2] 5e 9b [2] 70 9b [2] 4f 87 }

  condition:
    any of them
}