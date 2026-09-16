rule TTP_XOR_WriteProcessMemory_c838 {
  strings:
    $key_c838 = { 9f 4a [2] ad 68 [2] ab 5d [2] 85 5d [2] ba 41 }

  condition:
    any of them
}