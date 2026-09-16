rule TTP_XOR_WriteProcessMemory_cca8 {
  strings:
    $key_cca8 = { 9b da [2] a9 f8 [2] af cd [2] 81 cd [2] be d1 }

  condition:
    any of them
}