rule TTP_XOR_WriteProcessMemory_fcfa {
  strings:
    $key_fcfa = { ab 88 [2] 99 aa [2] 9f 9f [2] b1 9f [2] 8e 83 }

  condition:
    any of them
}