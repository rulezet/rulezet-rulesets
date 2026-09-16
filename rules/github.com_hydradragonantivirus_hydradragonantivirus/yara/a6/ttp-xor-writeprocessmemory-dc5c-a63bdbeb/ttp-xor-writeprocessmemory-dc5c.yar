rule TTP_XOR_WriteProcessMemory_dc5c {
  strings:
    $key_dc5c = { 8b 2e [2] b9 0c [2] bf 39 [2] 91 39 [2] ae 25 }

  condition:
    any of them
}