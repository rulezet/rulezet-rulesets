rule TTP_XOR_WriteProcessMemory_aadc {
  strings:
    $key_aadc = { fd ae [2] cf 8c [2] c9 b9 [2] e7 b9 [2] d8 a5 }

  condition:
    any of them
}