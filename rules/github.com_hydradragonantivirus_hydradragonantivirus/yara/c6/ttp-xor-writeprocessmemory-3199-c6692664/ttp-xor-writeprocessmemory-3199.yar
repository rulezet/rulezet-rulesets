rule TTP_XOR_WriteProcessMemory_3199 {
  strings:
    $key_3199 = { 66 eb [2] 54 c9 [2] 52 fc [2] 7c fc [2] 43 e0 }

  condition:
    any of them
}