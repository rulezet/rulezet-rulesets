rule TTP_XOR_WriteProcessMemory_0ae3 {
  strings:
    $key_0ae3 = { 5d 91 [2] 6f b3 [2] 69 86 [2] 47 86 [2] 78 9a }

  condition:
    any of them
}