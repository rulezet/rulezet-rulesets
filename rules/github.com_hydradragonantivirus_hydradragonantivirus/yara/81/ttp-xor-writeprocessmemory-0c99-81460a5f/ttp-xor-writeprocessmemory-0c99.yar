rule TTP_XOR_WriteProcessMemory_0c99 {
  strings:
    $key_0c99 = { 5b eb [2] 69 c9 [2] 6f fc [2] 41 fc [2] 7e e0 }

  condition:
    any of them
}