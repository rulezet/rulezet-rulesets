rule TTP_XOR_WriteProcessMemory_4bba {
  strings:
    $key_4bba = { 1c c8 [2] 2e ea [2] 28 df [2] 06 df [2] 39 c3 }

  condition:
    any of them
}