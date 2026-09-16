rule TTP_XOR_WriteProcessMemory_dcae {
  strings:
    $key_dcae = { 8b dc [2] b9 fe [2] bf cb [2] 91 cb [2] ae d7 }

  condition:
    any of them
}