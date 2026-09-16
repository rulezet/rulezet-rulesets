rule TTP_XOR_WriteProcessMemory_86ea {
  strings:
    $key_86ea = { d1 98 [2] e3 ba [2] e5 8f [2] cb 8f [2] f4 93 }

  condition:
    any of them
}