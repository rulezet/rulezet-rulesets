rule TTP_XOR_WriteProcessMemory_c8a8 {
  strings:
    $key_c8a8 = { 9f da [2] ad f8 [2] ab cd [2] 85 cd [2] ba d1 }

  condition:
    any of them
}