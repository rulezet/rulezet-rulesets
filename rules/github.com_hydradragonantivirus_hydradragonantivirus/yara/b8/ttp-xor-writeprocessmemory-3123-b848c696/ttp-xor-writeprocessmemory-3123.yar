rule TTP_XOR_WriteProcessMemory_3123 {
  strings:
    $key_3123 = { 66 51 [2] 54 73 [2] 52 46 [2] 7c 46 [2] 43 5a }

  condition:
    any of them
}