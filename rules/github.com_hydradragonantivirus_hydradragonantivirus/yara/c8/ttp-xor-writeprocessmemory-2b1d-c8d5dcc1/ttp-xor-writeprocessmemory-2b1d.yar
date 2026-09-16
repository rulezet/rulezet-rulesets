rule TTP_XOR_WriteProcessMemory_2b1d {
  strings:
    $key_2b1d = { 7c 6f [2] 4e 4d [2] 48 78 [2] 66 78 [2] 59 64 }

  condition:
    any of them
}