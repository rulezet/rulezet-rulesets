rule TTP_XOR_WriteProcessMemory_dc0d {
  strings:
    $key_dc0d = { 8b 7f [2] b9 5d [2] bf 68 [2] 91 68 [2] ae 74 }

  condition:
    any of them
}