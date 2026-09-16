rule TTP_XOR_WriteProcessMemory_04e3 {
  strings:
    $key_04e3 = { 53 91 [2] 61 b3 [2] 67 86 [2] 49 86 [2] 76 9a }

  condition:
    any of them
}