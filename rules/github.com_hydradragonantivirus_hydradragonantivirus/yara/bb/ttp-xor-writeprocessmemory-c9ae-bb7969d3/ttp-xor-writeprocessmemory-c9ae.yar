rule TTP_XOR_WriteProcessMemory_c9ae {
  strings:
    $key_c9ae = { 9e dc [2] ac fe [2] aa cb [2] 84 cb [2] bb d7 }

  condition:
    any of them
}