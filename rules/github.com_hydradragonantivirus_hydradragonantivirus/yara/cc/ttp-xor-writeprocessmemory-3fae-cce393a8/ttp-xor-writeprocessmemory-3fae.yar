rule TTP_XOR_WriteProcessMemory_3fae {
  strings:
    $key_3fae = { 68 dc [2] 5a fe [2] 5c cb [2] 72 cb [2] 4d d7 }

  condition:
    any of them
}