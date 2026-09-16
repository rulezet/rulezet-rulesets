rule TTP_XOR_WriteProcessMemory_c399 {
  strings:
    $key_c399 = { 94 eb [2] a6 c9 [2] a0 fc [2] 8e fc [2] b1 e0 }

  condition:
    any of them
}