rule TTP_XOR_WriteProcessMemory_e361 {
  strings:
    $key_e361 = { b4 13 [2] 86 31 [2] 80 04 [2] ae 04 [2] 91 18 }

  condition:
    any of them
}