rule TTP_XOR_WriteProcessMemory_7818 {
  strings:
    $key_7818 = { 2f 6a [2] 1d 48 [2] 1b 7d [2] 35 7d [2] 0a 61 }

  condition:
    any of them
}