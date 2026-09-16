rule TTP_XOR_WriteProcessMemory_035a {
  strings:
    $key_035a = { 54 28 [2] 66 0a [2] 60 3f [2] 4e 3f [2] 71 23 }

  condition:
    any of them
}