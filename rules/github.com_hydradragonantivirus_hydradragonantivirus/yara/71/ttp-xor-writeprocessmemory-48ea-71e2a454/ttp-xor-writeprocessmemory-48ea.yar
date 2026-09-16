rule TTP_XOR_WriteProcessMemory_48ea {
  strings:
    $key_48ea = { 1f 98 [2] 2d ba [2] 2b 8f [2] 05 8f [2] 3a 93 }

  condition:
    any of them
}