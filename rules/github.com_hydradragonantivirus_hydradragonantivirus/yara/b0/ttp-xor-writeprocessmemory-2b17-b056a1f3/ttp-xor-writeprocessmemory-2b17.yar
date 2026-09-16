rule TTP_XOR_WriteProcessMemory_2b17 {
  strings:
    $key_2b17 = { 7c 65 [2] 4e 47 [2] 48 72 [2] 66 72 [2] 59 6e }

  condition:
    any of them
}