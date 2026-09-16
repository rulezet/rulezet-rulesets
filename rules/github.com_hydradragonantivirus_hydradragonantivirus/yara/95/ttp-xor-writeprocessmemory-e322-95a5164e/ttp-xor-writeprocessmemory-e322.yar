rule TTP_XOR_WriteProcessMemory_e322 {
  strings:
    $key_e322 = { b4 50 [2] 86 72 [2] 80 47 [2] ae 47 [2] 91 5b }

  condition:
    any of them
}