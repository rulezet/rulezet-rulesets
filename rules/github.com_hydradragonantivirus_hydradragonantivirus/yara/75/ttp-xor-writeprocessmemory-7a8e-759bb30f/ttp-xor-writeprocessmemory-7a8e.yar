rule TTP_XOR_WriteProcessMemory_7a8e {
  strings:
    $key_7a8e = { 2d fc [2] 1f de [2] 19 eb [2] 37 eb [2] 08 f7 }

  condition:
    any of them
}