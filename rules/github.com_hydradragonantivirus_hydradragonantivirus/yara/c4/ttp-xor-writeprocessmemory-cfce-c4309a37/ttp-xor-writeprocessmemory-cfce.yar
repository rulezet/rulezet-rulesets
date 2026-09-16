rule TTP_XOR_WriteProcessMemory_cfce {
  strings:
    $key_cfce = { 98 bc [2] aa 9e [2] ac ab [2] 82 ab [2] bd b7 }

  condition:
    any of them
}