rule TTP_XOR_WriteProcessMemory_abdc {
  strings:
    $key_abdc = { fc ae [2] ce 8c [2] c8 b9 [2] e6 b9 [2] d9 a5 }

  condition:
    any of them
}