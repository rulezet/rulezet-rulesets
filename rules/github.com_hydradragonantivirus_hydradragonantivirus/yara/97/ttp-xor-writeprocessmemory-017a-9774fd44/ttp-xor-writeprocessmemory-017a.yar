rule TTP_XOR_WriteProcessMemory_017a {
  strings:
    $key_017a = { 56 08 [2] 64 2a [2] 62 1f [2] 4c 1f [2] 73 03 }

  condition:
    any of them
}