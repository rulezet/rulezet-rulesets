rule TTP_XOR_WriteProcessMemory_35fa {
  strings:
    $key_35fa = { 62 88 [2] 50 aa [2] 56 9f [2] 78 9f [2] 47 83 }

  condition:
    any of them
}