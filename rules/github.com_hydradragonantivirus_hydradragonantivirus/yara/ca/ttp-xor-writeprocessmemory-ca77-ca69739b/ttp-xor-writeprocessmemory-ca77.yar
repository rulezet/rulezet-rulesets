rule TTP_XOR_WriteProcessMemory_ca77 {
  strings:
    $key_ca77 = { 9d 05 [2] af 27 [2] a9 12 [2] 87 12 [2] b8 0e }

  condition:
    any of them
}