rule TTP_XOR_WriteProcessMemory_ffbe {
  strings:
    $key_ffbe = { a8 cc [2] 9a ee [2] 9c db [2] b2 db [2] 8d c7 }

  condition:
    any of them
}