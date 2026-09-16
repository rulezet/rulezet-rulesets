rule TTP_XOR_WriteProcessMemory_01e3 {
  strings:
    $key_01e3 = { 56 91 [2] 64 b3 [2] 62 86 [2] 4c 86 [2] 73 9a }

  condition:
    any of them
}