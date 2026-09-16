rule TTP_XOR_WriteProcessMemory_362c {
  strings:
    $key_362c = { 61 5e [2] 53 7c [2] 55 49 [2] 7b 49 [2] 44 55 }

  condition:
    any of them
}