rule TTP_XOR_WriteProcessMemory_ab61 {
  strings:
    $key_ab61 = { fc 13 [2] ce 31 [2] c8 04 [2] e6 04 [2] d9 18 }

  condition:
    any of them
}