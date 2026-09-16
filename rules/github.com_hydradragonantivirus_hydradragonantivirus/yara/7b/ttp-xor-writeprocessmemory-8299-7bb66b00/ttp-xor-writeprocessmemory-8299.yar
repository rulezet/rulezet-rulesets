rule TTP_XOR_WriteProcessMemory_8299 {
  strings:
    $key_8299 = { d5 eb [2] e7 c9 [2] e1 fc [2] cf fc [2] f0 e0 }

  condition:
    any of them
}