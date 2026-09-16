rule TTP_XOR_WriteProcessMemory_62ea {
  strings:
    $key_62ea = { 35 98 [2] 07 ba [2] 01 8f [2] 2f 8f [2] 10 93 }

  condition:
    any of them
}