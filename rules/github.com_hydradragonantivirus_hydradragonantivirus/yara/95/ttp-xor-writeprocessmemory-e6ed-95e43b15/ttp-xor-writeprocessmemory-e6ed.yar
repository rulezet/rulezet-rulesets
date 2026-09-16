rule TTP_XOR_WriteProcessMemory_e6ed {
  strings:
    $key_e6ed = { b1 9f [2] 83 bd [2] 85 88 [2] ab 88 [2] 94 94 }

  condition:
    any of them
}