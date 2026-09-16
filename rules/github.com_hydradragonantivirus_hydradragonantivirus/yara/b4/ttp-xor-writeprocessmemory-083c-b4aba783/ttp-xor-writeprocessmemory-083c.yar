rule TTP_XOR_WriteProcessMemory_083c {
  strings:
    $key_083c = { 5f 4e [2] 6d 6c [2] 6b 59 [2] 45 59 [2] 7a 45 }

  condition:
    any of them
}