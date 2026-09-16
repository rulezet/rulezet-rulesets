rule TTP_XOR_WriteProcessMemory_2717 {
  strings:
    $key_2717 = { 70 65 [2] 42 47 [2] 44 72 [2] 6a 72 [2] 55 6e }

  condition:
    any of them
}