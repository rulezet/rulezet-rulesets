rule TTP_XOR_WriteProcessMemory_24a8 {
  strings:
    $key_24a8 = { 73 da [2] 41 f8 [2] 47 cd [2] 69 cd [2] 56 d1 }

  condition:
    any of them
}