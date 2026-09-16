rule TTP_XOR_WriteProcessMemory_1be3 {
  strings:
    $key_1be3 = { 4c 91 [2] 7e b3 [2] 78 86 [2] 56 86 [2] 69 9a }

  condition:
    any of them
}