rule TTP_XOR_WriteProcessMemory_601a {
  strings:
    $key_601a = { 37 68 [2] 05 4a [2] 03 7f [2] 2d 7f [2] 12 63 }

  condition:
    any of them
}