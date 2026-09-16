rule TTP_XOR_WriteProcessMemory_6ea4 {
  strings:
    $key_6ea4 = { 39 d6 [2] 0b f4 [2] 0d c1 [2] 23 c1 [2] 1c dd }

  condition:
    any of them
}