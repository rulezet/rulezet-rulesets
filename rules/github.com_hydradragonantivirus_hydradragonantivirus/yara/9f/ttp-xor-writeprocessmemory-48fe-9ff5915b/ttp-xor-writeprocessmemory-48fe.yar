rule TTP_XOR_WriteProcessMemory_48fe {
  strings:
    $key_48fe = { 1f 8c [2] 2d ae [2] 2b 9b [2] 05 9b [2] 3a 87 }

  condition:
    any of them
}