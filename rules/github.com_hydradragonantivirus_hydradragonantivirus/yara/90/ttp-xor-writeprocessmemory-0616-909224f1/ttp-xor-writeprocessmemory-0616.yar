rule TTP_XOR_WriteProcessMemory_0616 {
  strings:
    $key_0616 = { 51 64 [2] 63 46 [2] 65 73 [2] 4b 73 [2] 74 6f }

  condition:
    any of them
}