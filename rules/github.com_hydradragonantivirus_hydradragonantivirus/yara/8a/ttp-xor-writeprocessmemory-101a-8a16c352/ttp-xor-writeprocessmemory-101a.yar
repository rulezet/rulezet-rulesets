rule TTP_XOR_WriteProcessMemory_101a {
  strings:
    $key_101a = { 47 68 [2] 75 4a [2] 73 7f [2] 5d 7f [2] 62 63 }

  condition:
    any of them
}