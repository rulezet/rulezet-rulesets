rule TTP_XOR_WriteProcessMemory_7647 {
  strings:
    $key_7647 = { 21 35 [2] 13 17 [2] 15 22 [2] 3b 22 [2] 04 3e }

  condition:
    any of them
}