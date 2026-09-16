rule TTP_XOR_WriteProcessMemory_7c38 {
  strings:
    $key_7c38 = { 2b 4a [2] 19 68 [2] 1f 5d [2] 31 5d [2] 0e 41 }

  condition:
    any of them
}