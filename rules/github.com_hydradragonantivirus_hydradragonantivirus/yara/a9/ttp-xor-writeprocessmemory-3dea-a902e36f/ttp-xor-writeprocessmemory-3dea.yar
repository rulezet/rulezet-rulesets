rule TTP_XOR_WriteProcessMemory_3dea {
  strings:
    $key_3dea = { 6a 98 [2] 58 ba [2] 5e 8f [2] 70 8f [2] 4f 93 }

  condition:
    any of them
}