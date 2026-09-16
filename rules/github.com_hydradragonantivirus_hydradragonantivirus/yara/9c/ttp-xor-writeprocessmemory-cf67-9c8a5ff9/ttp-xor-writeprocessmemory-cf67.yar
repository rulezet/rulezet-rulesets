rule TTP_XOR_WriteProcessMemory_cf67 {
  strings:
    $key_cf67 = { 98 15 [2] aa 37 [2] ac 02 [2] 82 02 [2] bd 1e }

  condition:
    any of them
}