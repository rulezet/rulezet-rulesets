rule TTP_XOR_WriteProcessMemory_f8ea {
  strings:
    $key_f8ea = { af 98 [2] 9d ba [2] 9b 8f [2] b5 8f [2] 8a 93 }

  condition:
    any of them
}