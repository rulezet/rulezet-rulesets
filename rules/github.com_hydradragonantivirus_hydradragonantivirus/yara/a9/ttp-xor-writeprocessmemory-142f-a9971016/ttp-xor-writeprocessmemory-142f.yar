rule TTP_XOR_WriteProcessMemory_142f {
  strings:
    $key_142f = { 43 5d [2] 71 7f [2] 77 4a [2] 59 4a [2] 66 56 }

  condition:
    any of them
}