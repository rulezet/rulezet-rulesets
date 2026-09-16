rule TTP_XOR_WriteProcessMemory_dcd7 {
  strings:
    $key_dcd7 = { 8b a5 [2] b9 87 [2] bf b2 [2] 91 b2 [2] ae ae }

  condition:
    any of them
}