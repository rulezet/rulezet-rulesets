rule TTP_XOR_WriteProcessMemory_03fa {
  strings:
    $key_03fa = { 54 88 [2] 66 aa [2] 60 9f [2] 4e 9f [2] 71 83 }

  condition:
    any of them
}