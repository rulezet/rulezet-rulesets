rule TTP_XOR_WriteProcessMemory_4be3 {
  strings:
    $key_4be3 = { 1c 91 [2] 2e b3 [2] 28 86 [2] 06 86 [2] 39 9a }

  condition:
    any of them
}