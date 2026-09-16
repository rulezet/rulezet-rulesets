rule TTP_XOR_WriteProcessMemory_6938 {
  strings:
    $key_6938 = { 3e 4a [2] 0c 68 [2] 0a 5d [2] 24 5d [2] 1b 41 }

  condition:
    any of them
}