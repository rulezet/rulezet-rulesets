rule TTP_XOR_WriteProcessMemory_e647 {
  strings:
    $key_e647 = { b1 35 [2] 83 17 [2] 85 22 [2] ab 22 [2] 94 3e }

  condition:
    any of them
}