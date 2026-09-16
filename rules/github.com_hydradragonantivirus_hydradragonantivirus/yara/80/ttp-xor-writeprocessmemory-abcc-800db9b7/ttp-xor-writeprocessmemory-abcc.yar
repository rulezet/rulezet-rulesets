rule TTP_XOR_WriteProcessMemory_abcc {
  strings:
    $key_abcc = { fc be [2] ce 9c [2] c8 a9 [2] e6 a9 [2] d9 b5 }

  condition:
    any of them
}