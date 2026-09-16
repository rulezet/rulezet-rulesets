rule TTP_XOR_WriteProcessMemory_4309 {
  strings:
    $key_4309 = { 14 7b [2] 26 59 [2] 20 6c [2] 0e 6c [2] 31 70 }

  condition:
    any of them
}