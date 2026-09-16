rule TTP_XOR_WriteProcessMemory_09ae {
  strings:
    $key_09ae = { 5e dc [2] 6c fe [2] 6a cb [2] 44 cb [2] 7b d7 }

  condition:
    any of them
}