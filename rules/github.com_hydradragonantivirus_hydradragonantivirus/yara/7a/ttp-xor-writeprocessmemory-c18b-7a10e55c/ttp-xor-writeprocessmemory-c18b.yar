rule TTP_XOR_WriteProcessMemory_c18b {
  strings:
    $key_c18b = { 96 f9 [2] a4 db [2] a2 ee [2] 8c ee [2] b3 f2 }

  condition:
    any of them
}