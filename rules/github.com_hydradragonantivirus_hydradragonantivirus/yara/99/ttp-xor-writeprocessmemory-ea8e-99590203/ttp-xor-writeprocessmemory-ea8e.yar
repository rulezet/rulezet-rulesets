rule TTP_XOR_WriteProcessMemory_ea8e {
  strings:
    $key_ea8e = { bd fc [2] 8f de [2] 89 eb [2] a7 eb [2] 98 f7 }

  condition:
    any of them
}