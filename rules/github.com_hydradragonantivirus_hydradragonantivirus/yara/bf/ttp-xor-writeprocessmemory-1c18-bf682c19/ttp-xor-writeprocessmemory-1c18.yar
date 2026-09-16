rule TTP_XOR_WriteProcessMemory_1c18 {
  strings:
    $key_1c18 = { 4b 6a [2] 79 48 [2] 7f 7d [2] 51 7d [2] 6e 61 }

  condition:
    any of them
}