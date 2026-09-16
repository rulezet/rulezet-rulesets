rule TTP_XOR_WriteProcessMemory_c8cb {
  strings:
    $key_c8cb = { 9f b9 [2] ad 9b [2] ab ae [2] 85 ae [2] ba b2 }

  condition:
    any of them
}