rule TTP_XOR_WriteProcessMemory_051e {
  strings:
    $key_051e = { 52 6c [2] 60 4e [2] 66 7b [2] 48 7b [2] 77 67 }

  condition:
    any of them
}