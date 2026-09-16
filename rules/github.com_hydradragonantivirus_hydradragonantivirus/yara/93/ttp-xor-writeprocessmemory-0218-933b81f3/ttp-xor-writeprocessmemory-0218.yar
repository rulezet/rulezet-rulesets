rule TTP_XOR_WriteProcessMemory_0218 {
  strings:
    $key_0218 = { 55 6a [2] 67 48 [2] 61 7d [2] 4f 7d [2] 70 61 }

  condition:
    any of them
}