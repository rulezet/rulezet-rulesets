rule TTP_XOR_WriteProcessMemory_e1fa {
  strings:
    $key_e1fa = { b6 88 [2] 84 aa [2] 82 9f [2] ac 9f [2] 93 83 }

  condition:
    any of them
}