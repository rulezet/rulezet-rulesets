rule TTP_XOR_WriteProcessMemory_dc3f {
  strings:
    $key_dc3f = { 8b 4d [2] b9 6f [2] bf 5a [2] 91 5a [2] ae 46 }

  condition:
    any of them
}