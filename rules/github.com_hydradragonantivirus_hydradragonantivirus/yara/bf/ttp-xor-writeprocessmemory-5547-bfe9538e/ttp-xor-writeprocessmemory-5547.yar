rule TTP_XOR_WriteProcessMemory_5547 {
  strings:
    $key_5547 = { 02 35 [2] 30 17 [2] 36 22 [2] 18 22 [2] 27 3e }

  condition:
    any of them
}