rule TTP_XOR_WriteProcessMemory_3bae {
  strings:
    $key_3bae = { 6c dc [2] 5e fe [2] 58 cb [2] 76 cb [2] 49 d7 }

  condition:
    any of them
}