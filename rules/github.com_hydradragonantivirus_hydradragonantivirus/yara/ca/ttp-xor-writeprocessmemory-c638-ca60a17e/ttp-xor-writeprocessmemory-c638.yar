rule TTP_XOR_WriteProcessMemory_c638 {
  strings:
    $key_c638 = { 91 4a [2] a3 68 [2] a5 5d [2] 8b 5d [2] b4 41 }

  condition:
    any of them
}