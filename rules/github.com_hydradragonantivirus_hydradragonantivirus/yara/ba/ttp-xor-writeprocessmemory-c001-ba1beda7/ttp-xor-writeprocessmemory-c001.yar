rule TTP_XOR_WriteProcessMemory_c001 {
  strings:
    $key_c001 = { 97 73 [2] a5 51 [2] a3 64 [2] 8d 64 [2] b2 78 }

  condition:
    any of them
}