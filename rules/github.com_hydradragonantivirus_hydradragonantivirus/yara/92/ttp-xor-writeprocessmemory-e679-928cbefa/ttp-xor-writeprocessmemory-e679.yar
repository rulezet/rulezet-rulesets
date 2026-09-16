rule TTP_XOR_WriteProcessMemory_e679 {
  strings:
    $key_e679 = { b1 0b [2] 83 29 [2] 85 1c [2] ab 1c [2] 94 00 }

  condition:
    any of them
}