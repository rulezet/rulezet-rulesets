rule TTP_XOR_WriteProcessMemory_0c18 {
  strings:
    $key_0c18 = { 5b 6a [2] 69 48 [2] 6f 7d [2] 41 7d [2] 7e 61 }

  condition:
    any of them
}