rule TTP_XOR_WriteProcessMemory_7978 {
  strings:
    $key_7978 = { 2e 0a [2] 1c 28 [2] 1a 1d [2] 34 1d [2] 0b 01 }

  condition:
    any of them
}