rule TTP_XOR_WriteProcessMemory_f4fa {
  strings:
    $key_f4fa = { a3 88 [2] 91 aa [2] 97 9f [2] b9 9f [2] 86 83 }

  condition:
    any of them
}