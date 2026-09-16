rule TTP_XOR_WriteProcessMemory_8e79 {
  strings:
    $key_8e79 = { d9 0b [2] eb 29 [2] ed 1c [2] c3 1c [2] fc 00 }

  condition:
    any of them
}