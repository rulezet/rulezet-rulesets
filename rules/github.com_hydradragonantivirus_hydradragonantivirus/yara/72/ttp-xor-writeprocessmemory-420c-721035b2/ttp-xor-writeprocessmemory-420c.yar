rule TTP_XOR_WriteProcessMemory_420c {
  strings:
    $key_420c = { 15 7e [2] 27 5c [2] 21 69 [2] 0f 69 [2] 30 75 }

  condition:
    any of them
}