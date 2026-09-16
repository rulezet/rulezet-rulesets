rule TTP_XOR_WriteProcessMemory_01ea {
  strings:
    $key_01ea = { 56 98 [2] 64 ba [2] 62 8f [2] 4c 8f [2] 73 93 }

  condition:
    any of them
}