rule TTP_XOR_WriteProcessMemory_942b {
  strings:
    $key_942b = { c3 59 [2] f1 7b [2] f7 4e [2] d9 4e [2] e6 52 }

  condition:
    any of them
}