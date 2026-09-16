rule TTP_XOR_WriteProcessMemory_7eae {
  strings:
    $key_7eae = { 29 dc [2] 1b fe [2] 1d cb [2] 33 cb [2] 0c d7 }

  condition:
    any of them
}