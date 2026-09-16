rule TTP_XOR_WriteProcessMemory_ffb9 {
  strings:
    $key_ffb9 = { a8 cb [2] 9a e9 [2] 9c dc [2] b2 dc [2] 8d c0 }

  condition:
    any of them
}