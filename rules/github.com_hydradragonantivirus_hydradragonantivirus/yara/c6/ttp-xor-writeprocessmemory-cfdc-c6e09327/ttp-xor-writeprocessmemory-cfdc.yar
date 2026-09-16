rule TTP_XOR_WriteProcessMemory_cfdc {
  strings:
    $key_cfdc = { 98 ae [2] aa 8c [2] ac b9 [2] 82 b9 [2] bd a5 }

  condition:
    any of them
}