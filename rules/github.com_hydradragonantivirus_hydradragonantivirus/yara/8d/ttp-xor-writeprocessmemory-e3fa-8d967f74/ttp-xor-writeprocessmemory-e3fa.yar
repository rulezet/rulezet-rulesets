rule TTP_XOR_WriteProcessMemory_e3fa {
  strings:
    $key_e3fa = { b4 88 [2] 86 aa [2] 80 9f [2] ae 9f [2] 91 83 }

  condition:
    any of them
}