rule TTP_XOR_WriteProcessMemory_e313 {
  strings:
    $key_e313 = { b4 61 [2] 86 43 [2] 80 76 [2] ae 76 [2] 91 6a }

  condition:
    any of them
}