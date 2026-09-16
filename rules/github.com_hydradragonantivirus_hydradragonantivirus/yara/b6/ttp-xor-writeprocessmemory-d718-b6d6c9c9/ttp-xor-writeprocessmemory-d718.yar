rule TTP_XOR_WriteProcessMemory_d718 {
  strings:
    $key_d718 = { 80 6a [2] b2 48 [2] b4 7d [2] 9a 7d [2] a5 61 }

  condition:
    any of them
}