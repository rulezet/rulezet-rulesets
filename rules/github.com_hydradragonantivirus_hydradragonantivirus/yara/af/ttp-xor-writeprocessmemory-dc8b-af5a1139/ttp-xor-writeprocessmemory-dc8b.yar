rule TTP_XOR_WriteProcessMemory_dc8b {
  strings:
    $key_dc8b = { 8b f9 [2] b9 db [2] bf ee [2] 91 ee [2] ae f2 }

  condition:
    any of them
}