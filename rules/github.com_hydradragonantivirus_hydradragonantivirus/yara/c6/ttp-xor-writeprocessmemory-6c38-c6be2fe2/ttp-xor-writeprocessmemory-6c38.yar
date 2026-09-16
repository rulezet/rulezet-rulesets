rule TTP_XOR_WriteProcessMemory_6c38 {
  strings:
    $key_6c38 = { 3b 4a [2] 09 68 [2] 0f 5d [2] 21 5d [2] 1e 41 }

  condition:
    any of them
}