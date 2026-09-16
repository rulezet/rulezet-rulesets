rule TTP_XOR_WriteProcessMemory_0099 {
  strings:
    $key_0099 = { 57 eb [2] 65 c9 [2] 63 fc [2] 4d fc [2] 72 e0 }

  condition:
    any of them
}