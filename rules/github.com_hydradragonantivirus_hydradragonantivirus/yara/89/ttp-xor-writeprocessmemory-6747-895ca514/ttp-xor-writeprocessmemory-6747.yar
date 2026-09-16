rule TTP_XOR_WriteProcessMemory_6747 {
  strings:
    $key_6747 = { 30 35 [2] 02 17 [2] 04 22 [2] 2a 22 [2] 15 3e }

  condition:
    any of them
}