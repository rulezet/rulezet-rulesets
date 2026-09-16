rule TTP_XOR_WriteProcessMemory_8631 {
  strings:
    $key_8631 = { d1 43 [2] e3 61 [2] e5 54 [2] cb 54 [2] f4 48 }

  condition:
    any of them
}