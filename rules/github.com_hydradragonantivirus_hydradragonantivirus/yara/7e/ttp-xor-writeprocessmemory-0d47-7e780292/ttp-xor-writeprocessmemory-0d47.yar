rule TTP_XOR_WriteProcessMemory_0d47 {
  strings:
    $key_0d47 = { 5a 35 [2] 68 17 [2] 6e 22 [2] 40 22 [2] 7f 3e }

  condition:
    any of them
}