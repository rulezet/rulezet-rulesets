rule TTP_XOR_WriteProcessMemory_4fae {
  strings:
    $key_4fae = { 18 dc [2] 2a fe [2] 2c cb [2] 02 cb [2] 3d d7 }

  condition:
    any of them
}