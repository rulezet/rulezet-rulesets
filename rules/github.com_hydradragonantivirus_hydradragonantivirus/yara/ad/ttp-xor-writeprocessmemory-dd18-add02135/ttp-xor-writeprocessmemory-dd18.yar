rule TTP_XOR_WriteProcessMemory_dd18 {
  strings:
    $key_dd18 = { 8a 6a [2] b8 48 [2] be 7d [2] 90 7d [2] af 61 }

  condition:
    any of them
}