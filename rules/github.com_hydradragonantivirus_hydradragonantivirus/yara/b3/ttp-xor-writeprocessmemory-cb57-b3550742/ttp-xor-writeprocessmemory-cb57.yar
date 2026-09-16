rule TTP_XOR_WriteProcessMemory_cb57 {
  strings:
    $key_cb57 = { 9c 25 [2] ae 07 [2] a8 32 [2] 86 32 [2] b9 2e }

  condition:
    any of them
}