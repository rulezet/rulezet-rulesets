rule TTP_XOR_WriteProcessMemory_eccb {
  strings:
    $key_eccb = { bb b9 [2] 89 9b [2] 8f ae [2] a1 ae [2] 9e b2 }

  condition:
    any of them
}