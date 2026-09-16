rule TTP_XOR_WriteProcessMemory_29ae {
  strings:
    $key_29ae = { 7e dc [2] 4c fe [2] 4a cb [2] 64 cb [2] 5b d7 }

  condition:
    any of them
}