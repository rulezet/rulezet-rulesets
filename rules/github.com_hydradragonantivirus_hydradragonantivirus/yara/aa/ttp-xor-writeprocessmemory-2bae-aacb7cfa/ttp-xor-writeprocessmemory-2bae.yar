rule TTP_XOR_WriteProcessMemory_2bae {
  strings:
    $key_2bae = { 7c dc [2] 4e fe [2] 48 cb [2] 66 cb [2] 59 d7 }

  condition:
    any of them
}