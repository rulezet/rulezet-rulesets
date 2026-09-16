rule TTP_XOR_WriteProcessMemory_70fd {
  strings:
    $key_70fd = { 27 8f [2] 15 ad [2] 13 98 [2] 3d 98 [2] 02 84 }

  condition:
    any of them
}