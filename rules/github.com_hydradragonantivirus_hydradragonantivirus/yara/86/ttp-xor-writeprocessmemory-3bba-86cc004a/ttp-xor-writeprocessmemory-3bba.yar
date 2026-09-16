rule TTP_XOR_WriteProcessMemory_3bba {
  strings:
    $key_3bba = { 6c c8 [2] 5e ea [2] 58 df [2] 76 df [2] 49 c3 }

  condition:
    any of them
}