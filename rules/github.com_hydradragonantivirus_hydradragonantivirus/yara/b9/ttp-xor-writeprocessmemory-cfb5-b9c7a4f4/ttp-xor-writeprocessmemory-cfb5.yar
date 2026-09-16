rule TTP_XOR_WriteProcessMemory_cfb5 {
  strings:
    $key_cfb5 = { 98 c7 [2] aa e5 [2] ac d0 [2] 82 d0 [2] bd cc }

  condition:
    any of them
}