rule TTP_XOR_WriteProcessMemory_211e {
  strings:
    $key_211e = { 76 6c [2] 44 4e [2] 42 7b [2] 6c 7b [2] 53 67 }

  condition:
    any of them
}