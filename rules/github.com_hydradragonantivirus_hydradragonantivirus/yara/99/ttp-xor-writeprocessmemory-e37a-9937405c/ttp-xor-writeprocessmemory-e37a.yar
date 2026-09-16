rule TTP_XOR_WriteProcessMemory_e37a {
  strings:
    $key_e37a = { b4 08 [2] 86 2a [2] 80 1f [2] ae 1f [2] 91 03 }

  condition:
    any of them
}