rule TTP_XOR_WriteProcessMemory_e333 {
  strings:
    $key_e333 = { b4 41 [2] 86 63 [2] 80 56 [2] ae 56 [2] 91 4a }

  condition:
    any of them
}