rule TTP_XOR_WriteProcessMemory_3dfd {
  strings:
    $key_3dfd = { 6a 8f [2] 58 ad [2] 5e 98 [2] 70 98 [2] 4f 84 }

  condition:
    any of them
}