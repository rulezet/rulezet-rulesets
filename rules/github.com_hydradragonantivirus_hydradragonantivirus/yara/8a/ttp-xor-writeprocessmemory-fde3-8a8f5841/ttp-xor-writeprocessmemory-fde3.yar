rule TTP_XOR_WriteProcessMemory_fde3 {
  strings:
    $key_fde3 = { aa 91 [2] 98 b3 [2] 9e 86 [2] b0 86 [2] 8f 9a }

  condition:
    any of them
}