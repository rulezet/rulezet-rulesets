rule TTP_XOR_WriteProcessMemory_21e3 {
  strings:
    $key_21e3 = { 76 91 [2] 44 b3 [2] 42 86 [2] 6c 86 [2] 53 9a }

  condition:
    any of them
}