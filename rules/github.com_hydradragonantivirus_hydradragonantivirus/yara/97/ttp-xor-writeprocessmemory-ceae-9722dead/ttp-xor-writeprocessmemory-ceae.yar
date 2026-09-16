rule TTP_XOR_WriteProcessMemory_ceae {
  strings:
    $key_ceae = { 99 dc [2] ab fe [2] ad cb [2] 83 cb [2] bc d7 }

  condition:
    any of them
}