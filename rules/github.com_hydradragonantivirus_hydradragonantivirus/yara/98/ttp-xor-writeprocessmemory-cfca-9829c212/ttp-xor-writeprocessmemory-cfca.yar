rule TTP_XOR_WriteProcessMemory_cfca {
  strings:
    $key_cfca = { 98 b8 [2] aa 9a [2] ac af [2] 82 af [2] bd b3 }

  condition:
    any of them
}