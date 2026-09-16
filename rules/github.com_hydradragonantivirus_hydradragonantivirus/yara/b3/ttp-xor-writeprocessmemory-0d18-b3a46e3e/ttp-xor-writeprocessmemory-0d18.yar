rule TTP_XOR_WriteProcessMemory_0d18 {
  strings:
    $key_0d18 = { 5a 6a [2] 68 48 [2] 6e 7d [2] 40 7d [2] 7f 61 }

  condition:
    any of them
}