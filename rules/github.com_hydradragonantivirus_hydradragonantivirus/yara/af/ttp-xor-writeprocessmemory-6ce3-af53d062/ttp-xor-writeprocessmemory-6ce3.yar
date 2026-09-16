rule TTP_XOR_WriteProcessMemory_6ce3 {
  strings:
    $key_6ce3 = { 3b 91 [2] 09 b3 [2] 0f 86 [2] 21 86 [2] 1e 9a }

  condition:
    any of them
}