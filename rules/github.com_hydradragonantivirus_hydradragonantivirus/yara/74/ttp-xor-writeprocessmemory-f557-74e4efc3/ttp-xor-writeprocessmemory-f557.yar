rule TTP_XOR_WriteProcessMemory_f557 {
  strings:
    $key_f557 = { a2 25 [2] 90 07 [2] 96 32 [2] b8 32 [2] 87 2e }

  condition:
    any of them
}