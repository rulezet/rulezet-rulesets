rule TTP_XOR_WriteProcessMemory_3be3 {
  strings:
    $key_3be3 = { 6c 91 [2] 5e b3 [2] 58 86 [2] 76 86 [2] 49 9a }

  condition:
    any of them
}