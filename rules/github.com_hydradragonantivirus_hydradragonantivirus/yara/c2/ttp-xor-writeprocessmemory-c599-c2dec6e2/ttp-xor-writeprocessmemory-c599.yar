rule TTP_XOR_WriteProcessMemory_c599 {
  strings:
    $key_c599 = { 92 eb [2] a0 c9 [2] a6 fc [2] 88 fc [2] b7 e0 }

  condition:
    any of them
}