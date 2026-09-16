rule TTP_XOR_WriteProcessMemory_6eae {
  strings:
    $key_6eae = { 39 dc [2] 0b fe [2] 0d cb [2] 23 cb [2] 1c d7 }

  condition:
    any of them
}