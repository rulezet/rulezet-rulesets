rule TTP_XOR_WriteProcessMemory_dfce {
  strings:
    $key_dfce = { 88 bc [2] ba 9e [2] bc ab [2] 92 ab [2] ad b7 }

  condition:
    any of them
}