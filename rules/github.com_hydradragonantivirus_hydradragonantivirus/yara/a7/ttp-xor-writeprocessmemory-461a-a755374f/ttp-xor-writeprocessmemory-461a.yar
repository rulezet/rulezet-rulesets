rule TTP_XOR_WriteProcessMemory_461a {
  strings:
    $key_461a = { 11 68 [2] 23 4a [2] 25 7f [2] 0b 7f [2] 34 63 }

  condition:
    any of them
}