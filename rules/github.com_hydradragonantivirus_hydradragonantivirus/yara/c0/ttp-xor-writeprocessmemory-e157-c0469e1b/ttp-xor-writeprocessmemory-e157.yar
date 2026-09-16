rule TTP_XOR_WriteProcessMemory_e157 {
  strings:
    $key_e157 = { b6 25 [2] 84 07 [2] 82 32 [2] ac 32 [2] 93 2e }

  condition:
    any of them
}