rule TTP_XOR_WriteProcessMemory_303c {
  strings:
    $key_303c = { 67 4e [2] 55 6c [2] 53 59 [2] 7d 59 [2] 42 45 }

  condition:
    any of them
}