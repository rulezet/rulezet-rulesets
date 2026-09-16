rule TTP_XOR_WriteProcessMemory_aacd {
  strings:
    $key_aacd = { fd bf [2] cf 9d [2] c9 a8 [2] e7 a8 [2] d8 b4 }

  condition:
    any of them
}