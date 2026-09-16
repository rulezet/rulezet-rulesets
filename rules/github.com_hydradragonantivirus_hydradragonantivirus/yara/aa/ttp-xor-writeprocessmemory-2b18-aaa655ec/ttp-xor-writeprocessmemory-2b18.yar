rule TTP_XOR_WriteProcessMemory_2b18 {
  strings:
    $key_2b18 = { 7c 6a [2] 4e 48 [2] 48 7d [2] 66 7d [2] 59 61 }

  condition:
    any of them
}