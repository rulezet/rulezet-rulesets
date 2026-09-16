rule TTP_XOR_WriteProcessMemory_c099 {
  strings:
    $key_c099 = { 97 eb [2] a5 c9 [2] a3 fc [2] 8d fc [2] b2 e0 }

  condition:
    any of them
}