rule TTP_XOR_WriteProcessMemory_c616 {
  strings:
    $key_c616 = { 91 64 [2] a3 46 [2] a5 73 [2] 8b 73 [2] b4 6f }

  condition:
    any of them
}