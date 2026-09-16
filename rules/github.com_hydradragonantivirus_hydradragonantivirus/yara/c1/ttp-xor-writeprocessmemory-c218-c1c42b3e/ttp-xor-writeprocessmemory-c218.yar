rule TTP_XOR_WriteProcessMemory_c218 {
  strings:
    $key_c218 = { 95 6a [2] a7 48 [2] a1 7d [2] 8f 7d [2] b0 61 }

  condition:
    any of them
}