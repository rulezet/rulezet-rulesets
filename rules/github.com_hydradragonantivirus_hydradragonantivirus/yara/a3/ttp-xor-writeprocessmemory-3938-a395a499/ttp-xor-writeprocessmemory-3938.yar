rule TTP_XOR_WriteProcessMemory_3938 {
  strings:
    $key_3938 = { 6e 4a [2] 5c 68 [2] 5a 5d [2] 74 5d [2] 4b 41 }

  condition:
    any of them
}