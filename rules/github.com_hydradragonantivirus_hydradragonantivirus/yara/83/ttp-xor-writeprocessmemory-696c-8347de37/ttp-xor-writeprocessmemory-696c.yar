rule TTP_XOR_WriteProcessMemory_696c {
  strings:
    $key_696c = { 3e 1e [2] 0c 3c [2] 0a 09 [2] 24 09 [2] 1b 15 }

  condition:
    any of them
}