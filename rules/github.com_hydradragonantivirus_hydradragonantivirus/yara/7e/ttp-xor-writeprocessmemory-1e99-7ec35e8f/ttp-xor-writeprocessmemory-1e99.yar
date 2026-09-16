rule TTP_XOR_WriteProcessMemory_1e99 {
  strings:
    $key_1e99 = { 49 eb [2] 7b c9 [2] 7d fc [2] 53 fc [2] 6c e0 }

  condition:
    any of them
}