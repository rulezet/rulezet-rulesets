rule TTP_XOR_WriteProcessMemory_daae {
  strings:
    $key_daae = { 8d dc [2] bf fe [2] b9 cb [2] 97 cb [2] a8 d7 }

  condition:
    any of them
}