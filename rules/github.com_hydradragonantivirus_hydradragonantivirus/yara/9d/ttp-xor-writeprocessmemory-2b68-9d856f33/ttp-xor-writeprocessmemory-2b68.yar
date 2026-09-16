rule TTP_XOR_WriteProcessMemory_2b68 {
  strings:
    $key_2b68 = { 7c 1a [2] 4e 38 [2] 48 0d [2] 66 0d [2] 59 11 }

  condition:
    any of them
}