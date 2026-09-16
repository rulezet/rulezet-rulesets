rule TTP_XOR_WriteProcessMemory_461f {
  strings:
    $key_461f = { 11 6d [2] 23 4f [2] 25 7a [2] 0b 7a [2] 34 66 }

  condition:
    any of them
}