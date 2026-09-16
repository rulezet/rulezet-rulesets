rule TTP_XOR_WriteProcessMemory_26e3 {
  strings:
    $key_26e3 = { 71 91 [2] 43 b3 [2] 45 86 [2] 6b 86 [2] 54 9a }

  condition:
    any of them
}