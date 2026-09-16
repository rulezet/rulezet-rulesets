rule TTP_XOR_WriteProcessMemory_e60c {
  strings:
    $key_e60c = { b1 7e [2] 83 5c [2] 85 69 [2] ab 69 [2] 94 75 }

  condition:
    any of them
}