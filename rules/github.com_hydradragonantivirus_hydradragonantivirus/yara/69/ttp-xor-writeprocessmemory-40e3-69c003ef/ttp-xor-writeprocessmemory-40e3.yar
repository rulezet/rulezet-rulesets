rule TTP_XOR_WriteProcessMemory_40e3 {
  strings:
    $key_40e3 = { 17 91 [2] 25 b3 [2] 23 86 [2] 0d 86 [2] 32 9a }

  condition:
    any of them
}