rule TTP_XOR_WriteProcessMemory_2218 {
  strings:
    $key_2218 = { 75 6a [2] 47 48 [2] 41 7d [2] 6f 7d [2] 50 61 }

  condition:
    any of them
}