rule TTP_XOR_WriteProcessMemory_bda8 {
  strings:
    $key_bda8 = { ea da [2] d8 f8 [2] de cd [2] f0 cd [2] cf d1 }

  condition:
    any of them
}