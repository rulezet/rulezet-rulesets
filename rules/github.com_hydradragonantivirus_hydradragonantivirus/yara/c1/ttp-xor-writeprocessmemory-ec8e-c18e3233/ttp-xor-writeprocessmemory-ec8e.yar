rule TTP_XOR_WriteProcessMemory_ec8e {
  strings:
    $key_ec8e = { bb fc [2] 89 de [2] 8f eb [2] a1 eb [2] 9e f7 }

  condition:
    any of them
}