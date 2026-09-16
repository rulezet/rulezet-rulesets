rule TTP_XOR_WriteProcessMemory_0f99 {
  strings:
    $key_0f99 = { 58 eb [2] 6a c9 [2] 6c fc [2] 42 fc [2] 7d e0 }

  condition:
    any of them
}