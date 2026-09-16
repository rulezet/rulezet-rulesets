rule TTP_XOR_WriteProcessMemory_dc16 {
  strings:
    $key_dc16 = { 8b 64 [2] b9 46 [2] bf 73 [2] 91 73 [2] ae 6f }

  condition:
    any of them
}