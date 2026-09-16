rule TTP_XOR_WriteProcessMemory_cda7 {
  strings:
    $key_cda7 = { 9a d5 [2] a8 f7 [2] ae c2 [2] 80 c2 [2] bf de }

  condition:
    any of them
}