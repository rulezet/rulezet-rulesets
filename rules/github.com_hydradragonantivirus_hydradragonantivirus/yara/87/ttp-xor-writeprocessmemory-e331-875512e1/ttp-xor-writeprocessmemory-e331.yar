rule TTP_XOR_WriteProcessMemory_e331 {
  strings:
    $key_e331 = { b4 43 [2] 86 61 [2] 80 54 [2] ae 54 [2] 91 48 }

  condition:
    any of them
}