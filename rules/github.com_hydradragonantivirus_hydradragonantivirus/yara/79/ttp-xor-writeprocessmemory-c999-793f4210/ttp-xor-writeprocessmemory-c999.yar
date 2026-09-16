rule TTP_XOR_WriteProcessMemory_c999 {
  strings:
    $key_c999 = { 9e eb [2] ac c9 [2] aa fc [2] 84 fc [2] bb e0 }

  condition:
    any of them
}