rule TTP_XOR_WriteProcessMemory_76ea {
  strings:
    $key_76ea = { 21 98 [2] 13 ba [2] 15 8f [2] 3b 8f [2] 04 93 }

  condition:
    any of them
}