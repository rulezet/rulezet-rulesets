rule TTP_XOR_WriteProcessMemory_e816 {
  strings:
    $key_e816 = { bf 64 [2] 8d 46 [2] 8b 73 [2] a5 73 [2] 9a 6f }

  condition:
    any of them
}