rule TTP_XOR_WriteProcessMemory_e323 {
  strings:
    $key_e323 = { b4 51 [2] 86 73 [2] 80 46 [2] ae 46 [2] 91 5a }

  condition:
    any of them
}