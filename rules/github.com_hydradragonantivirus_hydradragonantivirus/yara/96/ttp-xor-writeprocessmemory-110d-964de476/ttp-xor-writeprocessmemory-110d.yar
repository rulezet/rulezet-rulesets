rule TTP_XOR_WriteProcessMemory_110d {
  strings:
    $key_110d = { 46 7f [2] 74 5d [2] 72 68 [2] 5c 68 [2] 63 74 }

  condition:
    any of them
}