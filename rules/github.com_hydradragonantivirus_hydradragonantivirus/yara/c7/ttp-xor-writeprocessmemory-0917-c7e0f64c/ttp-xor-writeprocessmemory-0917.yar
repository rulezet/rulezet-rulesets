rule TTP_XOR_WriteProcessMemory_0917 {
  strings:
    $key_0917 = { 5e 65 [2] 6c 47 [2] 6a 72 [2] 44 72 [2] 7b 6e }

  condition:
    any of them
}