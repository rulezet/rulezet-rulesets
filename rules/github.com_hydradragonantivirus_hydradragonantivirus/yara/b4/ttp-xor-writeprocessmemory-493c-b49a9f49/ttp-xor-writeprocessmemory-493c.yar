rule TTP_XOR_WriteProcessMemory_493c {
  strings:
    $key_493c = { 1e 4e [2] 2c 6c [2] 2a 59 [2] 04 59 [2] 3b 45 }

  condition:
    any of them
}