rule TTP_XOR_WriteProcessMemory_66e3 {
  strings:
    $key_66e3 = { 31 91 [2] 03 b3 [2] 05 86 [2] 2b 86 [2] 14 9a }

  condition:
    any of them
}