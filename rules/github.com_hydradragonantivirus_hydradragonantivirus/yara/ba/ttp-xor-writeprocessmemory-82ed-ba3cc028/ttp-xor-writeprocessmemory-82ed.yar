rule TTP_XOR_WriteProcessMemory_82ed {
  strings:
    $key_82ed = { d5 9f [2] e7 bd [2] e1 88 [2] cf 88 [2] f0 94 }

  condition:
    any of them
}