rule TTP_XOR_WriteProcessMemory_eeae {
  strings:
    $key_eeae = { b9 dc [2] 8b fe [2] 8d cb [2] a3 cb [2] 9c d7 }

  condition:
    any of them
}