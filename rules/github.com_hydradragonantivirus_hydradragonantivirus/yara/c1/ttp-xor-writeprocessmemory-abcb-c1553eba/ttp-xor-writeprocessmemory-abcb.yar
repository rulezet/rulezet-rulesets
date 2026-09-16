rule TTP_XOR_WriteProcessMemory_abcb {
  strings:
    $key_abcb = { fc b9 [2] ce 9b [2] c8 ae [2] e6 ae [2] d9 b2 }

  condition:
    any of them
}