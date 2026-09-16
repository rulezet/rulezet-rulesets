rule TTP_XOR_WriteProcessMemory_e317 {
  strings:
    $key_e317 = { b4 65 [2] 86 47 [2] 80 72 [2] ae 72 [2] 91 6e }

  condition:
    any of them
}