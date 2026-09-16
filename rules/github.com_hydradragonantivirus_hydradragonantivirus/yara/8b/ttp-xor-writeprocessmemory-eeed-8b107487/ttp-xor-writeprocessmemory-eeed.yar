rule TTP_XOR_WriteProcessMemory_eeed {
  strings:
    $key_eeed = { b9 9f [2] 8b bd [2] 8d 88 [2] a3 88 [2] 9c 94 }

  condition:
    any of them
}