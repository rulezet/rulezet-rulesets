rule TTP_XOR_WriteProcessMemory_dcfa {
  strings:
    $key_dcfa = { 8b 88 [2] b9 aa [2] bf 9f [2] 91 9f [2] ae 83 }

  condition:
    any of them
}