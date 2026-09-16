rule TTP_XOR_WriteProcessMemory_e3cb {
  strings:
    $key_e3cb = { b4 b9 [2] 86 9b [2] 80 ae [2] ae ae [2] 91 b2 }

  condition:
    any of them
}