rule TTP_XOR_WriteProcessMemory_fcac {
  strings:
    $key_fcac = { ab de [2] 99 fc [2] 9f c9 [2] b1 c9 [2] 8e d5 }

  condition:
    any of them
}