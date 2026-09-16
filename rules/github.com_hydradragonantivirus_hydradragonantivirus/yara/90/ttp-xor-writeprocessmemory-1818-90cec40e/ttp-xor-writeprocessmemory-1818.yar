rule TTP_XOR_WriteProcessMemory_1818 {
  strings:
    $key_1818 = { 4f 6a [2] 7d 48 [2] 7b 7d [2] 55 7d [2] 6a 61 }

  condition:
    any of them
}