rule TTP_XOR_WriteProcessMemory_c80c {
  strings:
    $key_c80c = { 9f 7e [2] ad 5c [2] ab 69 [2] 85 69 [2] ba 75 }

  condition:
    any of them
}