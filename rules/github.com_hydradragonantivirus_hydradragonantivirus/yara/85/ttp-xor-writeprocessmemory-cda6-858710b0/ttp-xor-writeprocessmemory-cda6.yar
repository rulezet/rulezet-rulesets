rule TTP_XOR_WriteProcessMemory_cda6 {
  strings:
    $key_cda6 = { 9a d4 [2] a8 f6 [2] ae c3 [2] 80 c3 [2] bf df }

  condition:
    any of them
}