rule TTP_XOR_WriteProcessMemory_cda3 {
  strings:
    $key_cda3 = { 9a d1 [2] a8 f3 [2] ae c6 [2] 80 c6 [2] bf da }

  condition:
    any of them
}