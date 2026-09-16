rule TTP_XOR_WriteProcessMemory_3747 {
  strings:
    $key_3747 = { 60 35 [2] 52 17 [2] 54 22 [2] 7a 22 [2] 45 3e }

  condition:
    any of them
}