rule TTP_XOR_WriteProcessMemory_31fa {
  strings:
    $key_31fa = { 66 88 [2] 54 aa [2] 52 9f [2] 7c 9f [2] 43 83 }

  condition:
    any of them
}