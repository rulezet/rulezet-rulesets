rule TTP_XOR_WriteProcessMemory_8799 {
  strings:
    $key_8799 = { d0 eb [2] e2 c9 [2] e4 fc [2] ca fc [2] f5 e0 }

  condition:
    any of them
}