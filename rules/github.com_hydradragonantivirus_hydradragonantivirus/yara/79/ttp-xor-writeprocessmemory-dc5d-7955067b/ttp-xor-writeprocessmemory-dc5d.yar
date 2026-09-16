rule TTP_XOR_WriteProcessMemory_dc5d {
  strings:
    $key_dc5d = { 8b 2f [2] b9 0d [2] bf 38 [2] 91 38 [2] ae 24 }

  condition:
    any of them
}