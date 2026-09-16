rule TTP_XOR_WriteProcessMemory_2e99 {
  strings:
    $key_2e99 = { 79 eb [2] 4b c9 [2] 4d fc [2] 63 fc [2] 5c e0 }

  condition:
    any of them
}