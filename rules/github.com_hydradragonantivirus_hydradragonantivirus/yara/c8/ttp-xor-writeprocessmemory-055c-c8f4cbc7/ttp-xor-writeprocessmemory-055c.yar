rule TTP_XOR_WriteProcessMemory_055c {
  strings:
    $key_055c = { 52 2e [2] 60 0c [2] 66 39 [2] 48 39 [2] 77 25 }

  condition:
    any of them
}