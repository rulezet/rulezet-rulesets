rule TTP_XOR_WriteProcessMemory_6bae {
  strings:
    $key_6bae = { 3c dc [2] 0e fe [2] 08 cb [2] 26 cb [2] 19 d7 }

  condition:
    any of them
}