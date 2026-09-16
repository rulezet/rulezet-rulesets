rule TTP_XOR_WriteProcessMemory_102c {
  strings:
    $key_102c = { 47 5e [2] 75 7c [2] 73 49 [2] 5d 49 [2] 62 55 }

  condition:
    any of them
}