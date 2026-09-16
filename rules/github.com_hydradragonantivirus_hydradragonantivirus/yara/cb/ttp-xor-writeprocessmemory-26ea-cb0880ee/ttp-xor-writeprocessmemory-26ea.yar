rule TTP_XOR_WriteProcessMemory_26ea {
  strings:
    $key_26ea = { 71 98 [2] 43 ba [2] 45 8f [2] 6b 8f [2] 54 93 }

  condition:
    any of them
}