rule TTP_XOR_WriteProcessMemory_d18b {
  strings:
    $key_d18b = { 86 f9 [2] b4 db [2] b2 ee [2] 9c ee [2] a3 f2 }

  condition:
    any of them
}