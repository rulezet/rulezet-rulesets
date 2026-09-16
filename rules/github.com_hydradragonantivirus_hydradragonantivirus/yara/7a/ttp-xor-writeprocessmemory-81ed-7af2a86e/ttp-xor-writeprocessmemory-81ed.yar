rule TTP_XOR_WriteProcessMemory_81ed {
  strings:
    $key_81ed = { d6 9f [2] e4 bd [2] e2 88 [2] cc 88 [2] f3 94 }

  condition:
    any of them
}