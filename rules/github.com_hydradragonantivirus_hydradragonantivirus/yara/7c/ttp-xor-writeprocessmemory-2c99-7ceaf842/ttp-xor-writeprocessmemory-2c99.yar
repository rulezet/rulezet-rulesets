rule TTP_XOR_WriteProcessMemory_2c99 {
  strings:
    $key_2c99 = { 7b eb [2] 49 c9 [2] 4f fc [2] 61 fc [2] 5e e0 }

  condition:
    any of them
}