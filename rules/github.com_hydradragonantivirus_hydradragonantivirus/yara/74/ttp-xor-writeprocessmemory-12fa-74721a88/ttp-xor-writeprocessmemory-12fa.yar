rule TTP_XOR_WriteProcessMemory_12fa {
  strings:
    $key_12fa = { 45 88 [2] 77 aa [2] 71 9f [2] 5f 9f [2] 60 83 }

  condition:
    any of them
}