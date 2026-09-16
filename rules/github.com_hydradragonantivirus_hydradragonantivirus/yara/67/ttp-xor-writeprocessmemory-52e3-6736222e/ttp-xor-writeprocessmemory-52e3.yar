rule TTP_XOR_WriteProcessMemory_52e3 {
  strings:
    $key_52e3 = { 05 91 [2] 37 b3 [2] 31 86 [2] 1f 86 [2] 20 9a }

  condition:
    any of them
}