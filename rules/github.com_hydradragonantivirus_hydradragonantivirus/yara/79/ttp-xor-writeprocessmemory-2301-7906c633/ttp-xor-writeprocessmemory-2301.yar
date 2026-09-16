rule TTP_XOR_WriteProcessMemory_2301 {
  strings:
    $key_2301 = { 74 73 [2] 46 51 [2] 40 64 [2] 6e 64 [2] 51 78 }

  condition:
    any of them
}