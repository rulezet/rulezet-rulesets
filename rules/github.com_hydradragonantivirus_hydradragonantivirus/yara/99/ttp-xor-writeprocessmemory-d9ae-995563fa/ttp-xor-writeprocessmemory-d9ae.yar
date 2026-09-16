rule TTP_XOR_WriteProcessMemory_d9ae {
  strings:
    $key_d9ae = { 8e dc [2] bc fe [2] ba cb [2] 94 cb [2] ab d7 }

  condition:
    any of them
}