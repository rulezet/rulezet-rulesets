rule TTP_XOR_WriteProcessMemory_bba8 {
  strings:
    $key_bba8 = { ec da [2] de f8 [2] d8 cd [2] f6 cd [2] c9 d1 }

  condition:
    any of them
}