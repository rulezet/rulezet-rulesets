rule TTP_XOR_WriteProcessMemory_6443 {
  strings:
    $key_6443 = { 33 31 [2] 01 13 [2] 07 26 [2] 29 26 [2] 16 3a }

  condition:
    any of them
}