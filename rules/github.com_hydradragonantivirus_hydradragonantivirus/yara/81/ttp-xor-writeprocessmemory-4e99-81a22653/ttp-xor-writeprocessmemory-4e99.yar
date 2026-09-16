rule TTP_XOR_WriteProcessMemory_4e99 {
  strings:
    $key_4e99 = { 19 eb [2] 2b c9 [2] 2d fc [2] 03 fc [2] 3c e0 }

  condition:
    any of them
}