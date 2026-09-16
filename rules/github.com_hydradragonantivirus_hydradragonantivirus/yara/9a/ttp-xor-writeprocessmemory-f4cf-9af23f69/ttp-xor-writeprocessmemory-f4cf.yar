rule TTP_XOR_WriteProcessMemory_f4cf {
  strings:
    $key_f4cf = { a3 bd [2] 91 9f [2] 97 aa [2] b9 aa [2] 86 b6 }

  condition:
    any of them
}