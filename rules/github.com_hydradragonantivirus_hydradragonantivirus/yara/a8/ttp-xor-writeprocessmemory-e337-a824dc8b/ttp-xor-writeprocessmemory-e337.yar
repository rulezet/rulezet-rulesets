rule TTP_XOR_WriteProcessMemory_e337 {
  strings:
    $key_e337 = { b4 45 [2] 86 67 [2] 80 52 [2] ae 52 [2] 91 4e }

  condition:
    any of them
}