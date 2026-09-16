rule TTP_XOR_WriteProcessMemory_36e3 {
  strings:
    $key_36e3 = { 61 91 [2] 53 b3 [2] 55 86 [2] 7b 86 [2] 44 9a }

  condition:
    any of them
}