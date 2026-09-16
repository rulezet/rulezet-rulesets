rule TTP_XOR_WriteProcessMemory_e257 {
  strings:
    $key_e257 = { b5 25 [2] 87 07 [2] 81 32 [2] af 32 [2] 90 2e }

  condition:
    any of them
}