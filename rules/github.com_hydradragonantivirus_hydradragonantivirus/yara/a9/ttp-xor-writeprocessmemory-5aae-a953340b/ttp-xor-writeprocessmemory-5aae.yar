rule TTP_XOR_WriteProcessMemory_5aae {
  strings:
    $key_5aae = { 0d dc [2] 3f fe [2] 39 cb [2] 17 cb [2] 28 d7 }

  condition:
    any of them
}