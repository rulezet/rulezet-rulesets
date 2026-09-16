rule TTP_XOR_WriteProcessMemory_e623 {
  strings:
    $key_e623 = { b1 51 [2] 83 73 [2] 85 46 [2] ab 46 [2] 94 5a }

  condition:
    any of them
}