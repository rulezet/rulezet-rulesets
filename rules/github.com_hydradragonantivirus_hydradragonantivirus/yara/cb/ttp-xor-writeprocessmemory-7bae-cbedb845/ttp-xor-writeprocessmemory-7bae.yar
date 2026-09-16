rule TTP_XOR_WriteProcessMemory_7bae {
  strings:
    $key_7bae = { 2c dc [2] 1e fe [2] 18 cb [2] 36 cb [2] 09 d7 }

  condition:
    any of them
}