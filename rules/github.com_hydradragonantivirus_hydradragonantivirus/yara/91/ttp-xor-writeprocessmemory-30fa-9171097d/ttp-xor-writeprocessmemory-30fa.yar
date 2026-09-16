rule TTP_XOR_WriteProcessMemory_30fa {
  strings:
    $key_30fa = { 67 88 [2] 55 aa [2] 53 9f [2] 7d 9f [2] 42 83 }

  condition:
    any of them
}