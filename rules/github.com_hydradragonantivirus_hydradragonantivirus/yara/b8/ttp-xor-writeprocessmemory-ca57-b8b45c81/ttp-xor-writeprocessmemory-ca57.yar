rule TTP_XOR_WriteProcessMemory_ca57 {
  strings:
    $key_ca57 = { 9d 25 [2] af 07 [2] a9 32 [2] 87 32 [2] b8 2e }

  condition:
    any of them
}