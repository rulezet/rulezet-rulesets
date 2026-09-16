rule TTP_XOR_WriteProcessMemory_2c18 {
  strings:
    $key_2c18 = { 7b 6a [2] 49 48 [2] 4f 7d [2] 61 7d [2] 5e 61 }

  condition:
    any of them
}