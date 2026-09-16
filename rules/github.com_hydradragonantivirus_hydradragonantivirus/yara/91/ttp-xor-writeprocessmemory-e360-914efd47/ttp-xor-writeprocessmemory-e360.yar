rule TTP_XOR_WriteProcessMemory_e360 {
  strings:
    $key_e360 = { b4 12 [2] 86 30 [2] 80 05 [2] ae 05 [2] 91 19 }

  condition:
    any of them
}