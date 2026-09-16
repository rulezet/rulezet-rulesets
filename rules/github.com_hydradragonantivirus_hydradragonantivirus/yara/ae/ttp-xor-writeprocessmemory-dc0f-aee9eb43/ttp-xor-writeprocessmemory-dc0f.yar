rule TTP_XOR_WriteProcessMemory_dc0f {
  strings:
    $key_dc0f = { 8b 7d [2] b9 5f [2] bf 6a [2] 91 6a [2] ae 76 }

  condition:
    any of them
}