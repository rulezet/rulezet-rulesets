rule TTP_XOR_WriteProcessMemory_182c {
  strings:
    $key_182c = { 4f 5e [2] 7d 7c [2] 7b 49 [2] 55 49 [2] 6a 55 }

  condition:
    any of them
}