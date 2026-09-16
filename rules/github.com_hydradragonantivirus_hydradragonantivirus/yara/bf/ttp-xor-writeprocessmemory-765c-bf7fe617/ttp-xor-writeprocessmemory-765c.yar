rule TTP_XOR_WriteProcessMemory_765c {
  strings:
    $key_765c = { 21 2e [2] 13 0c [2] 15 39 [2] 3b 39 [2] 04 25 }

  condition:
    any of them
}