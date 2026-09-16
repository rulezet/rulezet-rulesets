rule TTP_XOR_WriteProcessMemory_9aa3 {
  strings:
    $key_9aa3 = { cd d1 [2] ff f3 [2] f9 c6 [2] d7 c6 [2] e8 da }

  condition:
    any of them
}