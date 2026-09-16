rule TTP_XOR_WriteProcessMemory_6e99 {
  strings:
    $key_6e99 = { 39 eb [2] 0b c9 [2] 0d fc [2] 23 fc [2] 1c e0 }

  condition:
    any of them
}