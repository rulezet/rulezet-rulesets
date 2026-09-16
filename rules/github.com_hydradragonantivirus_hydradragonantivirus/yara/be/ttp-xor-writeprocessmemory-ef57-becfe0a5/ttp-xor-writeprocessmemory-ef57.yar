rule TTP_XOR_WriteProcessMemory_ef57 {
  strings:
    $key_ef57 = { b8 25 [2] 8a 07 [2] 8c 32 [2] a2 32 [2] 9d 2e }

  condition:
    any of them
}