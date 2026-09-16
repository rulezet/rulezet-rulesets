rule TTP_XOR_WriteProcessMemory_cfb9 {
  strings:
    $key_cfb9 = { 98 cb [2] aa e9 [2] ac dc [2] 82 dc [2] bd c0 }

  condition:
    any of them
}