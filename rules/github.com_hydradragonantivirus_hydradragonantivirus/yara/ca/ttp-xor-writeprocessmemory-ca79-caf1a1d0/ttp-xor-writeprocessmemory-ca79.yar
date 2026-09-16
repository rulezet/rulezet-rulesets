rule TTP_XOR_WriteProcessMemory_ca79 {
  strings:
    $key_ca79 = { 9d 0b [2] af 29 [2] a9 1c [2] 87 1c [2] b8 00 }

  condition:
    any of them
}