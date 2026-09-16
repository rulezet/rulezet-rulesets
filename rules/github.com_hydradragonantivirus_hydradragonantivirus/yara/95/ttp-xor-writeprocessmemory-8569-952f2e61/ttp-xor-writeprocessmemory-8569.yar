rule TTP_XOR_WriteProcessMemory_8569 {
  strings:
    $key_8569 = { d2 1b [2] e0 39 [2] e6 0c [2] c8 0c [2] f7 10 }

  condition:
    any of them
}