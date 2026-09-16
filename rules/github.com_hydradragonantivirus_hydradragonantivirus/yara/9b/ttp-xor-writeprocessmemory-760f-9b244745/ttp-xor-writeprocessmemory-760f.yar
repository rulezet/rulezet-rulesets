rule TTP_XOR_WriteProcessMemory_760f {
  strings:
    $key_760f = { 21 7d [2] 13 5f [2] 15 6a [2] 3b 6a [2] 04 76 }

  condition:
    any of them
}