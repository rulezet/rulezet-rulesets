rule TTP_XOR_WriteProcessMemory_527d {
  strings:
    $key_527d = { 05 0f [2] 37 2d [2] 31 18 [2] 1f 18 [2] 20 04 }

  condition:
    any of them
}