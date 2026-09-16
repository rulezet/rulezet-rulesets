rule TTP_XOR_WriteProcessMemory_4c99 {
  strings:
    $key_4c99 = { 1b eb [2] 29 c9 [2] 2f fc [2] 01 fc [2] 3e e0 }

  condition:
    any of them
}