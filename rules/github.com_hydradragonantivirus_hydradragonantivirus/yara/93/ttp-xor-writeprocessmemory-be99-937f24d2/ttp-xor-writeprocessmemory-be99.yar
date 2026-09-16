rule TTP_XOR_WriteProcessMemory_be99 {
  strings:
    $key_be99 = { e9 eb [2] db c9 [2] dd fc [2] f3 fc [2] cc e0 }

  condition:
    any of them
}