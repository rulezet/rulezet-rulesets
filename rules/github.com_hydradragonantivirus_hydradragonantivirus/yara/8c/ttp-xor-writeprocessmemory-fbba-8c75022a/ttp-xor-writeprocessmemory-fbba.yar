rule TTP_XOR_WriteProcessMemory_fbba {
  strings:
    $key_fbba = { ac c8 [2] 9e ea [2] 98 df [2] b6 df [2] 89 c3 }

  condition:
    any of them
}