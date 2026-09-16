rule TTP_XOR_WriteProcessMemory_6799 {
  strings:
    $key_6799 = { 30 eb [2] 02 c9 [2] 04 fc [2] 2a fc [2] 15 e0 }

  condition:
    any of them
}