rule TTP_XOR_WriteProcessMemory_e633 {
  strings:
    $key_e633 = { b1 41 [2] 83 63 [2] 85 56 [2] ab 56 [2] 94 4a }

  condition:
    any of them
}