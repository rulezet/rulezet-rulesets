rule TTP_XOR_WriteProcessMemory_f4d8 {
  strings:
    $key_f4d8 = { a3 aa [2] 91 88 [2] 97 bd [2] b9 bd [2] 86 a1 }

  condition:
    any of them
}