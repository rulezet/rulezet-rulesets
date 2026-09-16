rule TTP_XOR_WriteProcessMemory_d299 {
  strings:
    $key_d299 = { 85 eb [2] b7 c9 [2] b1 fc [2] 9f fc [2] a0 e0 }

  condition:
    any of them
}