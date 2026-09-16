rule TTP_XOR_WriteProcessMemory_dc77 {
  strings:
    $key_dc77 = { 8b 05 [2] b9 27 [2] bf 12 [2] 91 12 [2] ae 0e }

  condition:
    any of them
}