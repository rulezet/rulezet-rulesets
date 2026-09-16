rule TTP_XOR_WriteProcessMemory_092c {
  strings:
    $key_092c = { 5e 5e [2] 6c 7c [2] 6a 49 [2] 44 49 [2] 7b 55 }

  condition:
    any of them
}